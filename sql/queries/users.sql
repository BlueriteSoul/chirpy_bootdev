-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),  -- Generate a new UUID for the user ID
    NOW(),              -- Set current timestamp for created_at
    NOW(),              -- Set current timestamp for updated_at
    $1,                 -- Use the email passed as the first parameter
    $2                  -- Password
)
RETURNING *;           -- Return the inserted row (all columns)

-- name: DropAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users
WHERE ID = $1;

-- name: UpdatePasswordAndEmail :one
UPDATE users
SET hashed_password = $1, email = $2, updated_at = NOW()
WHERE id = $3
RETURNING *;

-- name: UpgradeToChirpyRed :one
UPDATE users
SET is_chirpy_red = TRUE, updated_at = NOW()
WHERE id = $1
RETURNING *;