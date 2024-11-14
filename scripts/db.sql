-- Criar o banco de dados
CREATE DATABASE library_management;
USE library_management;

-- Tabela para Autores
CREATE TABLE authors (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

-- Tabela para Categorias
CREATE TABLE categories (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

-- Tabela para Livros
CREATE TABLE books (
    id VARCHAR(50) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    author_id VARCHAR(50),
    category_id VARCHAR(50),
    description TEXT,
    FOREIGN KEY (author_id) REFERENCES authors(id),
    FOREIGN KEY (category_id) REFERENCES categories(id)
);

-- Tabela para Comentários
CREATE TABLE comments (
    id VARCHAR(50) PRIMARY KEY,
    book_id VARCHAR(50),
    text TEXT NOT NULL,
    FOREIGN KEY (book_id) REFERENCES books(id)
);

-- Inserir alguns autores
INSERT INTO authors (id, name) VALUES ('1', 'J.K. Rowling');
INSERT INTO authors (id, name) VALUES ('2', 'J.R.R. Tolkien');

-- Inserir algumas categorias
INSERT INTO categories (id, name) VALUES ('1', 'Fantasy');
INSERT INTO categories (id, name) VALUES ('2', 'Adventure');

-- Inserir alguns livros
INSERT INTO books (id, title, author_id, category_id, description) VALUES ('1', 'Harry Potter and the Philosopher''s Stone', '1', '1', 'A young boy discovers he is a wizard on his 11th birthday.');
INSERT INTO books (id, title, author_id, category_id, description) VALUES ('2', 'The Hobbit', '2', '2', 'A hobbit embarks on a grand adventure to reclaim a lost kingdom.');

-- Inserir alguns comentários
INSERT INTO comments (id, book_id, text) VALUES ('1', '1', 'Amazing book! A must-read for everyone.');
INSERT INTO comments (id, book_id, text) VALUES ('2', '2', 'A timeless classic that never gets old.');
