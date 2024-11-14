package database

import (
	"api-crud-go/models"
	"database/sql"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func InitDB(dsn string) {
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal(err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatal(err)
	}
}

func GetBooks() ([]models.Book, error) {
	rows, err := DB.Query("SELECT id, title, author_id, category_id, description FROM books")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var books []models.Book
	for rows.Next() {
		var book models.Book
		if err := rows.Scan(&book.ID, &book.Title, &book.AuthorID, &book.CategoryID, &book.Description); err != nil {
			return nil, err
		}
		books = append(books, book)
	}
	return books, nil
}

func GetBookByID(id string) (models.Book, error) {
	var book models.Book
	err := DB.QueryRow("SELECT id, title, author_id, category_id, description FROM books WHERE id = ?", id).Scan(&book.ID, &book.Title, &book.AuthorID, &book.CategoryID, &book.Description)
	return book, err
}

func PostBook(newBook models.Book) error {
	_, err := DB.Exec("INSERT INTO books (id, title, author_id, category_id, description) VALUES (?, ?, ?, ?, ?)", newBook.ID, newBook.Title, newBook.AuthorID, newBook.CategoryID, newBook.Description)
	return err
}

func UpdateBook(id string, updatedBook models.Book) error {
	_, err := DB.Exec("UPDATE books SET title = ?, author_id = ?, category_id = ?, description = ? WHERE id = ?", updatedBook.Title, updatedBook.AuthorID, updatedBook.CategoryID, updatedBook.Description, id)
	return err
}

func DeleteBook(id string) error {
	_, err := DB.Exec("DELETE FROM books WHERE id = ?", id)
	return err
}

func PostComment(newComment models.Comment) error {
	_, err := DB.Exec("INSERT INTO comments (id, book_id, text) VALUES (?, ?, ?)", newComment.ID, newComment.BookID, newComment.Text)
	return err
}
