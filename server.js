const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const SECRET_KEY = 'sua_chave_secreta_super_segura'; // Mude isto para uma chave mais segura

// Configuração da Pool de Conexão com o PostgreSQL
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'sigshow',
    password: 'admin',
    port: 5432,
});


// Middlewares
app.use(cors());
app.use(express.json());

// Rota de Teste
app.get('/', (req, res) => {
    res.send('Servidor do SigShow está funcionando!');
});

// Rota de Login
app.post('/login', async (req, res) => {
    const { nome, senha } = req.body;
    if (!nome || !senha) {
        return res.status(400).json({ message: 'Nome e senha são obrigatórios.' });
    }
    let client;
    try {
        client = await pool.connect();
        let userResult, userType;

        // Tenta encontrar como organizador
        userResult = await client.query('SELECT * FROM organizador WHERE nome = $1', [nome]);
        userType = 'organizador';

        // Se não encontrar, tenta como admin
        if (userResult.rows.length === 0) {
            userResult = await client.query('SELECT * FROM admin WHERE nome = $1', [nome]);
            userType = 'admin';
        }

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: 'Utilizador não encontrado.' });
        }

        const user = userResult.rows[0];
        
        const isPasswordValid = (senha === user.senha);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Senha inválida.' });
        }
        
        const tokenPayload = {
            id: user.id_organizador || user.id_admin,
            nome: user.nome,
            type: userType
        };

        const token = jwt.sign(tokenPayload, SECRET_KEY, { expiresIn: '1h' });
        
        res.json({ 
            message: 'Login bem-sucedido!', 
            token,
            user: tokenPayload
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    } finally {
        if (client) client.release();
    }
});

// Middleware de Autenticação
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Rota para Registar Organizador
app.post('/register/organizador', async (req, res) => {
    const { nome, senha, nome_empresa } = req.body;
    if (!nome || !senha || !nome_empresa) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }
    try {
        const hashedSenha = await bcrypt.hash(senha, 10);
        await pool.query(
            'INSERT INTO organizador (nome, senha, nome_empresa) VALUES ($1, $2, $3)',
            [nome, hashedSenha, nome_empresa]
        );
        res.status(201).json({ message: 'Organizador registado com sucesso!' });
    } catch (error) {
        console.error('Erro ao registar organizador:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// --- ROTAS DE EVENTOS ---

// Obter um evento específico (público)
app.get('/eventos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query('SELECT nome FROM evento WHERE id_evento = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Evento não encontrado.' });
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar evento:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// NOVA ROTA - Obter todos os eventos patrocinados (público)
app.get('/eventos/patrocinados', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id_evento, nome, descricao, latitude, longitude, cidade 
             FROM evento 
             WHERE patrocinado = TRUE 
             ORDER BY data_inicio ASC`
        );
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar eventos patrocinados:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// Obter eventos do organizador logado (protegido)
app.get('/meus-eventos', authenticateToken, async (req, res) => {
    try {
        const id_organizador = req.user.id;
        const result = await pool.query('SELECT id_evento, nome FROM evento WHERE id_organizador = $1 ORDER BY nome ASC', [id_organizador]);
        res.json(result.rows);
    } catch (error) {
        console.error('Erro ao buscar eventos do utilizador:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Criar um novo evento (protegido)
app.post('/eventos', authenticateToken, async (req, res) => {
    const { nome, data_inicio, data_fim, horario_inicio, horario_fim, site_venda, descricao, id_categoria, latitude, longitude, endereco, cidade, patrocinado } = req.body;
    const id_organizador = req.user.id;

    // Apenas admins podem definir um evento como patrocinado
    const isPatrocinado = (req.user.type === 'admin' && patrocinado === true);

    try {
        const query = `
            INSERT INTO evento (nome, data_inicio, data_fim, horario_inicio, horario_fim, site_venda, descricao, id_categoria, id_organizador, latitude, longitude, endereco, cidade, patrocinado)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *;
        `;
        const values = [nome, data_inicio, data_fim, horario_inicio, horario_fim, site_venda, descricao, id_categoria, id_organizador, latitude, longitude, endereco, cidade, isPatrocinado];
        const result = await pool.query(query, values);
        res.status(201).json({ message: 'Evento criado com sucesso!', evento: result.rows[0] });
    } catch (error) {
        console.error('Erro ao criar evento:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// Remover um evento (protegido)
app.delete('/eventos/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const user = req.user;
    try {
        const eventoResult = await pool.query('SELECT id_organizador FROM evento WHERE id_evento = $1', [id]);
        if (eventoResult.rows.length === 0) {
            return res.status(404).json({ message: 'Evento não encontrado.' });
        }
        const evento = eventoResult.rows[0];
        if (user.type !== 'admin' && user.id !== evento.id_organizador) {
            return res.status(403).json({ message: 'Acesso negado. Não tem permissão para remover este evento.' });
        }
        await pool.query('DELETE FROM local_venda WHERE id_evento = $1', [id]);
        await pool.query('DELETE FROM evento WHERE id_evento = $1', [id]);
        res.json({ message: 'Evento e locais de venda associados foram removidos com sucesso.' });
    } catch (error) {
        console.error('Erro ao remover evento:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// --- ROTAS DE LOCAIS DE VENDA ---

// Criar um novo local de venda (protegido)
app.post('/locais-venda', authenticateToken, async (req, res) => {
    const { nome, id_evento, latitude, longitude, endereco, cidade } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO local_venda (nome, id_evento, latitude, longitude, endereco, cidade) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [nome, id_evento, latitude, longitude, endereco, cidade]
        );
        res.status(201).json({ message: 'Local de venda criado com sucesso!', local: result.rows[0] });
    } catch (error) {
        console.error('Erro ao criar local de venda:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Remover um local de venda (protegido)
app.delete('/locais-venda/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const user = req.user;
    try {
        const localResult = await pool.query(
            'SELECT E.id_organizador FROM local_venda LV JOIN evento E ON LV.id_evento = E.id_evento WHERE LV.id_local_venda = $1', 
            [id]
        );
        if (localResult.rows.length === 0) {
            return res.status(404).json({ message: 'Local de venda não encontrado.' });
        }
        const local = localResult.rows[0];
        if (user.type !== 'admin' && user.id !== local.id_organizador) {
            return res.status(403).json({ message: 'Acesso negado.' });
        }
        await pool.query('DELETE FROM local_venda WHERE id_local_venda = $1', [id]);
        res.json({ message: 'Local de venda removido com sucesso.' });
    } catch (error) {
        console.error('Erro ao remover local de venda:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Iniciar o Servidor
app.listen(port, () => {
    console.log(`Servidor do SigShow rodando em http://localhost:${port}`);
});

