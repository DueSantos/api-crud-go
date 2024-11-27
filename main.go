package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Estruturas
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Book struct {
	ID          int    `json:"id"`
	Title       string `json:"title"`
	AuthorID    int    `json:"author_id"`
	CategoryID  int    `json:"category_id"`
	ISBN        string `json:"isbn"`
	PublishDate string `json:"publish_date"`
}

type Author struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Biography string `json:"biography"`
}

type Category struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var db *sql.DB
var jwtKey = []byte("chave_secreta")

func main() {
	// Conexão com o banco de dados
	var err error
	db, err = sql.Open("mysql", "root@tcp(localhost:3306)/biblioteca")
	// se caso o banco tiver login e senha vai ficar assim.
	// db, err = sql.Open("mysql", "login:senha@tcp(localhost:3306)/biblioteca")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Configuração do Router
	r := mux.NewRouter()

	// Rotas de autenticação
	r.HandleFunc("/api/register", registerHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/login", loginHandler).Methods("POST", "OPTIONS")

	// Rotas de livros
	r.HandleFunc("/api/books", authMiddleware(createBook, "admin")).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/books", authMiddleware(getBooks, "user")).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/books/{id}", authMiddleware(getBook, "user")).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/books/{id}", authMiddleware(updateBook, "admin")).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/books/{id}", authMiddleware(deleteBook, "admin")).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/books/search", authMiddleware(searchBooks, "user")).Methods("GET", "OPTIONS")

	// Rotas de autores
	r.HandleFunc("/api/authors", authMiddleware(createAuthor, "admin")).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/authors", authMiddleware(getAuthors, "user")).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/authors/{id}", authMiddleware(getAuthor, "user")).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/authors/{id}", authMiddleware(updateAuthor, "admin")).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/authors/{id}", authMiddleware(deleteAuthor, "admin")).Methods("DELETE", "OPTIONS")

	// Rotas de categorias
	r.HandleFunc("/api/categories", authMiddleware(createCategory, "admin")).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/categories", authMiddleware(getCategories, "user")).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/categories/{id}", authMiddleware(getCategory, "user")).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/categories/{id}", authMiddleware(updateCategory, "admin")).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/categories/{id}", authMiddleware(deleteCategory, "admin")).Methods("DELETE", "OPTIONS")

	log.Println("Servidor rodando na porta 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}

// Middleware de autenticação
func authMiddleware(next func(http.ResponseWriter, *http.Request), role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Habilitar CORS para desenvolvimento
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// Verificar método OPTIONS (pre-flight request)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Token não fornecido", http.StatusUnauthorized)
			return
		}

		// Remover o prefixo "Bearer " se existir
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("método de assinatura inesperado: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil {
			http.Error(w, "Token inválido: "+err.Error(), http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Verificar se o ID do usuário existe nas claims
			userID, ok := claims["sub"].(string)
			if !ok {
				http.Error(w, "Token não contém ID do usuário", http.StatusUnauthorized)
				return
			}

			// Verificar role do usuário
			var userRole string
			err = db.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&userRole)
			if err != nil {
				if err == sql.ErrNoRows {
					http.Error(w, "Usuário não encontrado", http.StatusUnauthorized)
				} else {
					log.Printf("Erro ao verificar role: %v", err)
					http.Error(w, "Erro ao verificar permissões", http.StatusInternalServerError)
				}
				return
			}

			// Verificar permissões
			if role == "admin" && userRole != "admin" {
				http.Error(w, "Acesso não autorizado", http.StatusForbidden)
				return
			}

			// Adicionar informações do usuário no contexto da requisição
			ctx := context.WithValue(r.Context(), "userID", userID)
			ctx = context.WithValue(ctx, "userRole", userRole)
			next(w, r.WithContext(ctx))
		} else {
			http.Error(w, "Token inválido", http.StatusUnauthorized)
		}
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Erro ao decodificar dados do usuário", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Erro ao criar usuário", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
		user.Username, string(hashedPassword), user.Role)
	if err != nil {
		http.Error(w, "Erro ao criar usuário", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	// Apenas uma chamada para w.WriteHeader
	response := map[string]string{
		"message": "Usuário criado com sucesso!",
	}
	// Escreve o status e a resposta ao mesmo tempo
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Erro ao decodificar dados do usuário", http.StatusBadRequest)
		return
	}

	var dbUser User
	err := db.QueryRow("SELECT id, password, role FROM users WHERE username = ?",
		user.Username).Scan(&dbUser.ID, &dbUser.Password, &dbUser.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Usuário não encontrado", http.StatusUnauthorized)
		} else {
			log.Printf("Erro ao buscar usuário: %v", err)
			http.Error(w, "Erro ao autenticar usuário", http.StatusInternalServerError)
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(user.Password)); err != nil {
		http.Error(w, "Senha incorreta", http.StatusUnauthorized)
		return
	}

	// Criar token com mais informações
	claims := jwt.MapClaims{
		"sub":  strconv.Itoa(dbUser.ID),
		"role": dbUser.Role,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("Erro ao gerar token: %v", err)
		http.Error(w, "Erro ao gerar token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Login realizado com sucesso!",
		"token":   tokenString,
		"role":    dbUser.Role,
	})
}

func createBook(w http.ResponseWriter, r *http.Request) {
	var book Book
	err := json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		http.Error(w, "Erro ao decodificar dados do livro: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Verificar se os campos obrigatórios estão preenchidos
	if book.Title == "" || book.AuthorID == 0 || book.CategoryID == 0 {
		http.Error(w, "Campos obrigatórios não preenchidos", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO books (title, author_id, category_id, isbn, publish_date) VALUES (?, ?, ?, ?, ?)",
		book.Title, book.AuthorID, book.CategoryID, book.ISBN, book.PublishDate)
	if err != nil {
		http.Error(w, "Erro ao criar livro: "+err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	book.ID = int(id)

	// Definir cabeçalho de resposta JSON
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message": "Livro criado com sucesso!",
		"book":    book,
	}

	json.NewEncoder(w).Encode(response)
}

func getBooks(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
        SELECT b.id, b.title, b.isbn, b.publish_date, 
               a.name as author_name, c.name as category_name 
        FROM books b 
        JOIN authors a ON b.author_id = a.id 
        JOIN categories c ON b.category_id = c.id
    `)
	if err != nil {
		http.Error(w, "Erro ao buscar livros", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var books []map[string]interface{}
	for rows.Next() {
		var id int
		var title, isbn, publishDate, authorName, categoryName string

		// Lendo os dados retornados pelo banco de dados
		err := rows.Scan(&id, &title, &isbn, &publishDate, &authorName, &categoryName)
		if err != nil {
			http.Error(w, "Erro ao ler dados dos livros", http.StatusInternalServerError)
			return
		}

		// Criando o mapa para representar o livro
		book := map[string]interface{}{
			"id":            id,
			"title":         title,
			"isbn":          isbn,
			"publish_date":  publishDate,
			"author_name":   authorName,
			"category_name": categoryName,
		}

		books = append(books, book)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(books)
}

func searchBooks(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	searchType := r.URL.Query().Get("type") // title, author, category

	var rows *sql.Rows
	var err error

	switch searchType {
	case "title":
		rows, err = db.Query(`
            SELECT b.id, b.title, b.isbn, b.publish_date, a.name as author_name, c.name as category_name 
            FROM books b 
            JOIN authors a ON b.author_id = a.id 
            JOIN categories c ON b.category_id = c.id 
            WHERE b.title LIKE ?
        `, "%"+query+"%")
	case "author":
		rows, err = db.Query(`
            SELECT b.id, b.title, b.isbn, b.publish_date, a.name as author_name, c.name as category_name 
            FROM books b 
            JOIN authors a ON b.author_id = a.id 
            JOIN categories c ON b.category_id = c.id 
            WHERE a.name LIKE ?
        `, "%"+query+"%")
	case "category":
		rows, err = db.Query(`
            SELECT b.id, b.title, b.isbn, b.publish_date, a.name as author_name, c.name as category_name 
            FROM books b 
            JOIN authors a ON b.author_id = a.id 
            JOIN categories c ON b.category_id = c.id 
            WHERE c.name LIKE ?
        `, "%"+query+"%")
	default:
		http.Error(w, "Tipo de busca inválido", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Erro na busca: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var books []map[string]interface{}
	for rows.Next() {
		var id int
		var title, isbn, publishDate, authorName, categoryName string

		err := rows.Scan(&id, &title, &isbn, &publishDate, &authorName, &categoryName)
		if err != nil {
			http.Error(w, "Erro ao processar resultados: "+err.Error(), http.StatusInternalServerError)
			return
		}

		book := map[string]interface{}{
			"id":            id,
			"title":         title,
			"isbn":          isbn,
			"publish_date":  publishDate,
			"author_name":   authorName,
			"category_name": categoryName,
		}
		books = append(books, book)
	}

	// Configurar cabeçalho da resposta JSON
	w.Header().Set("Content-Type", "application/json")

	// Verificar se há resultados
	if len(books) == 0 {
		response := map[string]string{
			"message": "Nenhum livro encontrado",
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Mensagem de sucesso com os resultados
	response := map[string]interface{}{
		"message": "Busca realizada com sucesso!",
		"books":   books,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func getBook(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var book struct {
		ID           int    `json:"id"`
		Title        string `json:"title"`
		ISBN         string `json:"isbn"`
		PublishDate  string `json:"publish_date"`
		AuthorName   string `json:"author_name"`
		CategoryName string `json:"category_name"`
	}

	err := db.QueryRow(`
        SELECT b.id, b.title, b.isbn, b.publish_date, a.name as author_name, c.name as category_name 
        FROM books b 
        JOIN authors a ON b.author_id = a.id 
        JOIN categories c ON b.category_id = c.id 
        WHERE b.id = ?`, id).Scan(
		&book.ID, &book.Title, &book.ISBN, &book.PublishDate, &book.AuthorName, &book.CategoryName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Livro não encontrado", http.StatusNotFound)
			return
		}
		http.Error(w, "Erro ao buscar livro: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Configurar cabeçalho da resposta JSON
	w.Header().Set("Content-Type", "application/json")

	// Resposta com mensagem de sucesso e os dados do livro
	response := map[string]interface{}{
		"message": "Livro encontrado com sucesso!",
		"book":    book,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func updateBook(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var book Book
	err := json.NewDecoder(r.Body).Decode(&book)
	if err != nil {
		http.Error(w, "Erro ao decodificar os dados do livro", http.StatusBadRequest)
		return
	}

	// Atualizar livro no banco de dados
	result, err := db.Exec(`
        UPDATE books 
        SET title = ?, author_id = ?, category_id = ?, isbn = ?, publish_date = ? 
        WHERE id = ?`,
		book.Title, book.AuthorID, book.CategoryID, book.ISBN, book.PublishDate, id)

	if err != nil {
		http.Error(w, "Erro ao atualizar livro", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Livro não encontrado", http.StatusNotFound)
		return
	}

	// Configurar cabeçalho da resposta JSON
	w.Header().Set("Content-Type", "application/json")

	// Adicionar o ID atualizado ao objeto livro
	book.ID = parseInt(id)

	// Resposta com mensagem de sucesso e o livro atualizado
	response := map[string]interface{}{
		"message": "Livro atualizado com sucesso!",
		"book":    book,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func deleteBook(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	result, err := db.Exec("DELETE FROM books WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Erro ao deletar livro", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Livro não encontrado", http.StatusNotFound)
		return
	}

	// Configurar cabeçalho da resposta JSON
	w.Header().Set("Content-Type", "application/json")

	// Resposta com mensagem de sucesso
	response := map[string]string{
		"message": "Livro deletado com sucesso!",
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func createAuthor(w http.ResponseWriter, r *http.Request) {
	var author Author
	if err := json.NewDecoder(r.Body).Decode(&author); err != nil {
		http.Error(w, "Erro ao decodificar dados do autor", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO authors (name, biography) VALUES (?, ?)",
		author.Name, author.Biography)
	if err != nil {
		http.Error(w, "Erro ao criar autor", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	author.ID = int(id)

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message": "Autor criado com sucesso!",
		"author":  author,
	}

	json.NewEncoder(w).Encode(response)
}

func getAuthors(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT * FROM authors")
	if err != nil {
		http.Error(w, "Erro ao buscar autores", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var authors []Author
	for rows.Next() {
		var author Author
		err := rows.Scan(&author.ID, &author.Name, &author.Biography)
		if err != nil {
			continue
		}
		authors = append(authors, author)
	}

	json.NewEncoder(w).Encode(authors)
}

func getAuthor(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var author Author
	err := db.QueryRow("SELECT * FROM authors WHERE id = ?", id).Scan(
		&author.ID, &author.Name, &author.Biography)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Autor não encontrado", http.StatusNotFound)
			return
		}
		http.Error(w, "Erro ao buscar autor", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(author)
}

func updateAuthor(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var author Author
	json.NewDecoder(r.Body).Decode(&author)

	_, err := db.Exec("UPDATE authors SET name = ?, biography = ? WHERE id = ?",
		author.Name, author.Biography, id)

	if err != nil {
		http.Error(w, "Erro ao atualizar autor", http.StatusInternalServerError)
		return
	}

	author.ID = parseInt(id)
	json.NewEncoder(w).Encode(author)
}

func deleteAuthor(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	result, err := db.Exec("DELETE FROM authors WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Erro ao deletar autor", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Autor não encontrado", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func createCategory(w http.ResponseWriter, r *http.Request) {
	var category Category
	if err := json.NewDecoder(r.Body).Decode(&category); err != nil {
		http.Error(w, "Erro ao decodificar dados da categoria", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO categories (name, description) VALUES (?, ?)",
		category.Name, category.Description)
	if err != nil {
		http.Error(w, "Erro ao criar categoria", http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()
	category.ID = int(id)

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"message":  "Categoria criada com sucesso!",
		"category": category,
	}

	json.NewEncoder(w).Encode(response)
}

func getCategories(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, description FROM categories")
	if err != nil {
		http.Error(w, "Erro ao buscar categorias: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		var category Category
		err := rows.Scan(&category.ID, &category.Name, &category.Description)
		if err != nil {
			http.Error(w, "Erro ao processar uma categoria: "+err.Error(), http.StatusInternalServerError)
			return
		}
		categories = append(categories, category)
	}

	// Configurar cabeçalho da resposta JSON
	w.Header().Set("Content-Type", "application/json")

	// Responder com mensagem de sucesso e dados
	response := map[string]interface{}{
		"message":    "Categorias buscadas com sucesso!",
		"categories": categories,
	}

	json.NewEncoder(w).Encode(response)
}

func getCategory(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var category Category
	err := db.QueryRow("SELECT id, name, description FROM categories WHERE id = ?", id).Scan(
		&category.ID, &category.Name, &category.Description)

	// Configurar cabeçalho de resposta JSON
	w.Header().Set("Content-Type", "application/json")

	if err != nil {
		if err == sql.ErrNoRows {
			// Resposta para categoria não encontrada
			response := map[string]string{
				"message": "Categoria não encontrada",
			}
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(response)
			return
		}

		// Resposta para outros erros
		response := map[string]string{
			"message": "Erro ao buscar categoria",
			"error":   err.Error(),
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Resposta de sucesso com a categoria encontrada
	response := map[string]interface{}{
		"message":  "Categoria encontrada com sucesso!",
		"category": category,
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func updateCategory(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	var category Category
	json.NewDecoder(r.Body).Decode(&category)

	_, err := db.Exec("UPDATE categories SET name = ?, description = ? WHERE id = ?",
		category.Name, category.Description, id)

	if err != nil {
		http.Error(w, "Erro ao atualizar categoria", http.StatusInternalServerError)
		return
	}

	category.ID = parseInt(id)
	json.NewEncoder(w).Encode(category)
}

func deleteCategory(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	id := params["id"]

	// Tentar excluir a categoria
	result, err := db.Exec("DELETE FROM categories WHERE id = ?", id)
	if err != nil {
		http.Error(w, "Erro ao deletar categoria: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Verificar se alguma linha foi afetada
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Categoria não encontrada", http.StatusNotFound)
		return
	}

	// Configurar cabeçalho da resposta JSON
	w.Header().Set("Content-Type", "application/json")

	// Mensagem de sucesso
	response := map[string]string{
		"message": "Categoria deletada com sucesso!",
		"id":      id,
	}

	// Enviar resposta
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Função auxiliar para converter string para int
func parseInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
