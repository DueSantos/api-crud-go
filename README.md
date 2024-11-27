# API de Biblioteca

nome da equipe:
João Luiz Silva - ADS
André Queiroz Rocha - Engenharia da Computação

Este projeto é uma API para gerenciamento de uma biblioteca, onde usuários podem cadastrar livros, autores e categorias, além de realizar buscas e gerenciar dados. A API possui autenticação baseada em JWT para segurança e controle de permissões.

## Funcionalidades

### Autenticação de Usuários
- Cadastro de novos usuários.
- Login com geração de token JWT para autenticação.

### Gerenciamento de Livros
- Criação, leitura, atualização e exclusão de livros.
- Busca de livros por título, autor ou categoria.

### Gerenciamento de Autores e Categorias
- Criação, leitura, atualização e exclusão de autores e categorias.

## Tecnologias Utilizadas

- **Go**: Linguagem de programação principal para a API.
- **MySQL**: Banco de dados relacional usado para armazenar os dados.
- **JWT**: Autenticação com tokens JWT para segurança.
- **Gorilla Mux**: Roteamento HTTP em Go.

## Endpoints

### Autenticação

- **POST /api/register**: Registra um novo usuário.
- **POST /api/login**: Realiza o login e retorna um token JWT.

### Livros

- **POST /api/books**: Cria um novo livro (Apenas para administradores).
- **GET /api/books**: Lista todos os livros.
- **GET /api/books/{id}**: Obtém detalhes de um livro pelo ID.
- **PUT /api/books/{id}**: Atualiza um livro pelo ID (Apenas para administradores).
- **DELETE /api/books/{id}**: Deleta um livro pelo ID (Apenas para administradores).
- **GET /api/books/search**: Busca livros por título, autor ou categoria.

### Autores

- **POST /api/authors**: Cria um novo autor (Apenas para administradores).
- **GET /api/authors**: Lista todos os autores.
- **GET /api/authors/{id}**: Obtém detalhes de um autor pelo ID.
- **PUT /api/authors/{id}**: Atualiza um autor pelo ID (Apenas para administradores).
- **DELETE /api/authors/{id}**: Deleta um autor pelo ID (Apenas para administradores).

### Categorias

- **POST /api/categories**: Cria uma nova categoria (Apenas para administradores).
- **GET /api/categories**: Lista todas as categorias.
- **GET /api/categories/{id}**: Obtém detalhes de uma categoria pelo ID.
- **PUT /api/categories/{id}**: Atualiza uma categoria pelo ID (Apenas para administradores).
- **DELETE /api/categories/{id}**: Deleta uma categoria pelo ID (Apenas para administradores).

## Como Rodar o Projeto

### Requisitos

- Go (versão 1.18 ou superior)
- MySQL (ou MariaDB)

### Configuração do Banco de Dados

1. Crie um banco de dados no MySQL com o nome `biblioteca` (ou altere no código conforme necessário).
2. Certifique-se de que o banco tenha as tabelas `users`, `books`, `authors` e `categories`. Você pode criar as tabelas com as instruções SQL apropriadas.

### Rodando a Aplicação

1. Clone o repositório:

    ```bash
    git clone https://github.com/usuario/projeto.git
    cd projeto
    ```

2. Instale as dependências:

    ```bash
    go mod tidy
    ```

3. Execute o servidor:

    ```bash
    go run main.go
    ```

O servidor estará rodando na porta 8080.

## Testando a API

Você pode usar ferramentas como **Postman** ou **cURL** para testar os endpoints da API.
