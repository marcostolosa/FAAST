-- Inicialização do banco de dados para o aplicativo Flask vulnerável

-- Criação de tabelas
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Inserção de dados de exemplo
INSERT INTO users (username, password, role) VALUES
('admin', 'admin123', 'admin'),
('user', 'password123', 'user'),
('test', 'test123', 'user');

-- Mensagens de exemplo
INSERT INTO messages (user_id, content) VALUES
(1, 'Esta é uma mensagem do admin'),
(2, 'Esta é uma mensagem do usuário normal'),
(3, 'Teste de <b>formatação HTML</b> em mensagens');