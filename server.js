// server.js

// 1. IMPORTAÇÃO DOS PACOTES
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');



// 2. CONFIGURAÇÃO INICIAL
const app = express();
const port = 3000;
const jwtSecret = 'seu_segredo_super_secreto_para_jwt';

app.use(cors());
app.use(express.json());

// 3. CONFIGURAÇÃO DA CONEXÃO COM O BANCO DE DADOS
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'sigshow',
    password: 'admin',
    port: 5432,
});

// 4. MIDDLEWARE DE AUTENTICAÇÃO
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.status(401).json({ message: 'Token não fornecido.' });

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: 'Token inválido.' });
        req.user = user;
        next();
    });
}

// 5. ROTAS (ENDPOINTS)

// Rota de Login
app.post('/login', async (req, res) => {
    const { nome, senha } = req.body;
    if (!nome || !senha) return res.status(400).json({ message: 'Nome e senha são obrigatórios.' });

    try {
        let userResult = await pool.query('SELECT * FROM admin WHERE nome = $1', [nome]);
        let userType = 'admin';

        if (userResult.rows.length === 0) {
            userResult = await pool.query('SELECT * FROM organizador WHERE nome = $1', [nome]);
            userType = 'organizador';
        }

        if (userResult.rows.length === 0) return res.status(401).json({ message: 'Utilizador não encontrado.' });
        
        const user = userResult.rows[0];
        if (senha !== user.senha) return res.status(401).json({ message: 'Senha inválida.' });

        const tokenPayload = { id: user.id_admin || user.id_organizador, nome: user.nome, type: userType };
        const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login bem-sucedido!', token, user: tokenPayload });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Rota para buscar eventos do organizador
app.get('/meus-eventos', authenticateToken, async (req, res) => {
    const id_organizador = req.user.id;
    try {
        const eventosResult = await pool.query('SELECT id_evento, nome FROM evento WHERE id_organizador = $1 ORDER BY nome ASC', [id_organizador]);
        res.status(200).json(eventosResult.rows);
    } catch (error) {
        console.error('Erro ao buscar eventos:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Rota para buscar o nome de um evento específico (para o pop-up do local de venda)
app.get('/eventos/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const eventoResult = await pool.query('SELECT nome FROM evento WHERE id_evento = $1', [id]);
        if (eventoResult.rows.length === 0) {
            return res.status(404).json({ message: 'Evento não encontrado.' });
        }
        res.status(200).json(eventoResult.rows[0]);
    } catch (error) {
        console.error('Erro ao buscar nome do evento:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// Rotas de Cadastro
app.post('/eventos', authenticateToken, async (req, res) => {
    const id_organizador = req.user.id;
    const { nome, data_inicio, data_fim, horario_inicio, horario_fim, site_venda, descricao, id_categoria, latitude, longitude, endereco, cidade } = req.body;
    try {
        const novoEvento = await pool.query(
            `INSERT INTO evento (nome, data_inicio, data_fim, horario_inicio, horario_fim, site_venda, descricao, id_categoria, id_organizador, latitude, longitude, endereco, cidade)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id_evento`,
            [nome, data_inicio, data_fim, horario_inicio, horario_fim, site_venda, descricao, id_categoria, id_organizador, latitude, longitude, endereco, cidade]
        );
        const id_novo_evento = novoEvento.rows[0].id_evento;
        await pool.query(`UPDATE evento SET geometria = ST_SetSRID(ST_MakePoint($1, $2), 4326) WHERE id_evento = $3`, [longitude, latitude, id_novo_evento]);
        res.status(201).json({ message: 'Evento criado com sucesso!', evento: novoEvento.rows[0] });
    } catch (error) {
        console.error('Erro ao criar evento:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.post('/locais-venda', authenticateToken, async (req, res) => {
    const { nome, id_evento, latitude, longitude, endereco, cidade } = req.body;
    try {
        const novoLocal = await pool.query(
            `INSERT INTO local_venda (nome, id_evento, latitude, longitude, endereco, cidade)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING id_local_venda`,
            [nome, id_evento, latitude, longitude, endereco, cidade]
        );
        const id_novo_local = novoLocal.rows[0].id_local_venda;
        await pool.query(`UPDATE local_venda SET geometria = ST_SetSRID(ST_MakePoint($1, $2), 4326) WHERE id_local_venda = $3`, [longitude, latitude, id_novo_local]);
        res.status(201).json({ message: 'Local de venda criado com sucesso!', local: novoLocal.rows[0] });
    } catch (error) {
        console.error('Erro ao criar local de venda:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

// ROTAS DE REMOÇÃO
app.delete('/eventos/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { id: userId, type: userType } = req.user;

    try {
        const eventResult = await pool.query('SELECT id_organizador FROM evento WHERE id_evento = $1', [id]);
        if (eventResult.rows.length === 0) {
            return res.status(404).json({ message: 'Evento não encontrado.' });
        }
        const eventOwnerId = eventResult.rows[0].id_organizador;

        if (userType !== 'admin' && userId !== eventOwnerId) {
            return res.status(403).json({ message: 'Não tem permissão para remover este evento.' });
        }

        await pool.query('DELETE FROM local_venda WHERE id_evento = $1', [id]);
        await pool.query('DELETE FROM evento WHERE id_evento = $1', [id]);

        res.status(200).json({ message: 'Evento e locais associados foram removidos com sucesso.' });
    } catch (error) {
        console.error('Erro ao remover evento:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});

app.delete('/locais-venda/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { id: userId, type: userType } = req.user;

    try {
        const locationResult = await pool.query(
            `SELECT e.id_organizador FROM local_venda lv
             JOIN evento e ON lv.id_evento = e.id_evento
             WHERE lv.id_local_venda = $1`,
            [id]
        );
        if (locationResult.rows.length === 0) {
            return res.status(404).json({ message: 'Local de venda não encontrado.' });
        }
        const eventOwnerId = locationResult.rows[0].id_organizador;

        if (userType !== 'admin' && userId !== eventOwnerId) {
            return res.status(403).json({ message: 'Não tem permissão para remover este local de venda.' });
        }

        await pool.query('DELETE FROM local_venda WHERE id_local_venda = $1', [id]);
        res.status(200).json({ message: 'Local de venda removido com sucesso.' });
    } catch (error) {
        console.error('Erro ao remover local de venda:', error);
        res.status(500).json({ message: 'Erro interno do servidor.' });
    }
});


// 6. INICIALIZAÇÃO DO SERVIDOR
app.listen(port, () => {
    console.log(`Servidor do SigShow rodando em http://localhost:${port}`);
});
