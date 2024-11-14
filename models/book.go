package models

type Book struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	AuthorID    string `json:"author_id"`
	CategoryID  string `json:"category_id"`
	Description string `json:"description"`
}
