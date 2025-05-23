package models

type Usuario struct {
	Firebase_uid string `json:"firebase_uid"`
	DisplayName  string `json:"display_name"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	// Admin       bool   `json:"admin"`
	// Id primitive.ObjectID `bson:"_id,omitempty"`
}
