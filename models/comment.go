package models

type Comment struct {
	ID     string `json:"id"`
	BookID string `json:"book_id"`
	Text   string `json:"text"`
}
