import tkinter as tk
from tkinter import messagebox
from pymongo import MongoClient
from cryptography.fernet import Fernet
import bcrypt
import random
from datetime import datetime, timedelta

# Conectar ao MongoDB com a base de dados "HospitalBD"
client = MongoClient("mongodb+srv://root:123@cluster0.aw9p5.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
db = client['HospitalBD']  # Nome do banco de dados

# Gerar chave de criptografia uma vez (armazenar em local seguro)
chave = Fernet.generate_key()
fernet = Fernet(chave)


# Função para criptografar dados
def criptografar_dados(dados):
    return fernet.encrypt(dados.encode('utf-8'))


# Função para descriptografar dados
def descriptografar_dados(dados_criptografados):
    return fernet.decrypt(dados_criptografados).decode('utf-8')


# Função para criar um novo usuário
def criar_usuario(nome, email, senha, cargo, autenticacao_2fa):
    senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
    usuario = {
        "nome": nome,
        "email": email,
        "senha_hash": senha_hash,
        "cargo": cargo,
        "autenticacao_2fa": autenticacao_2fa,
        "ultimo_login": None,
        "permissoes": ["criar_registro", "visualizar_registro", "compartilhar_registro"]
    }
    db.usuarios.insert_one(usuario)
    messagebox.showinfo("Sucesso", "Usuário criado com sucesso!")


# Função para criar um registro médico
def criar_registro(nome_paciente, historico, tratamento, medico_id):
    dados = f"{nome_paciente};{historico};{tratamento}"
    dados_criptografados = criptografar_dados(dados)

    registro = {
        "dados": dados_criptografados,
        "timestamp_criacao": datetime.utcnow(),
        "created_by": medico_id,  # ID do médico
        "historico": historico,
        "compartilhado_com": []
    }
    db.registros.insert_one(registro)
    messagebox.showinfo("Sucesso", "Registro médico criado com sucesso!")


# Função para acessar e visualizar o registro médico
def visualizar_registro(id_registro):
    registro = db.registros.find_one({"_id": id_registro})
    if registro:
        dados_criptografados = registro["dados"]
        dados = descriptografar_dados(dados_criptografados)
        nome_paciente, historico, tratamento = dados.split(';')

        # Exibir informações na interface
        resultado.set(f"Paciente: {nome_paciente}\nHistórico: {historico}\nTratamento: {tratamento}")
    else:
        messagebox.showerror("Erro", "Registro não encontrado.")


# Função de autenticação 2FA
def gerar_token_2fa(usuario_id):
    token = random.randint(100000, 999999)
    data_expiracao = datetime.utcnow() + timedelta(minutes=10)

    token_2fa = {
        "usuario_id": usuario_id,
        "token_2fa": token,
        "timestamp_expiracao": data_expiracao,
        "usado": False
    }

    db.autenticacao.insert_one(token_2fa)
    return token


# Função para autenticar o usuário
def autenticar_usuario(email, senha, token_2fa):
    usuario = db.usuarios.find_one({"email": email})
    if usuario and bcrypt.checkpw(senha.encode('utf-8'), usuario['senha_hash']):
        # Verificar o token 2FA
        token = db.autenticacao.find_one({"usuario_id": usuario["_id"], "usado": False})
        if token and token["token_2fa"] == int(token_2fa):
            db.autenticacao.update_one({"_id": token["_id"]}, {"$set": {"usado": True}})
            messagebox.showinfo("Sucesso", "Autenticação realizada com sucesso!")
            return usuario["_id"]
        else:
            messagebox.showerror("Erro", "Token 2FA inválido ou expirado.")
    else:
        messagebox.showerror("Erro", "Usuário ou senha inválidos.")
    return None


# Função para inicializar a interface gráfica
def iniciar_interface():
    # Criando a janela principal
    janela = tk.Tk()
    janela.title("Sistema de Gerenciamento de Registros Médicos")
    janela.geometry("400x400")

    # Definir variáveis
    global resultado
    resultado = tk.StringVar()

    # Tela de login
    def tela_login():
        # Campos para login
        tk.Label(janela, text="E-mail:").grid(row=0, column=0)
        email_entry = tk.Entry(janela)
        email_entry.grid(row=0, column=1)

        tk.Label(janela, text="Senha:").grid(row=1, column=0)
        senha_entry = tk.Entry(janela, show="*")
        senha_entry.grid(row=1, column=1)

        tk.Label(janela, text="Token 2FA:").grid(row=2, column=0)
        token_2fa_entry = tk.Entry(janela)
        token_2fa_entry.grid(row=2, column=1)

        def autenticar():
            usuario_id = autenticar_usuario(email_entry.get(), senha_entry.get(), token_2fa_entry.get())
            if usuario_id:
                # Abrir tela de gerenciamento de registros
                tela_registro(usuario_id)

        tk.Button(janela, text="Login", command=autenticar).grid(row=3, column=1)

    def tela_registro(usuario_id):
        # Tela de gerenciamento de registros médicos
        tk.Label(janela, text="Criar Novo Registro Médico").grid(row=0, column=0, columnspan=2)

        tk.Label(janela, text="Nome do Paciente:").grid(row=1, column=0)
        nome_entry = tk.Entry(janela)
        nome_entry.grid(row=1, column=1)

        tk.Label(janela, text="Histórico Médico:").grid(row=2, column=0)
        historico_entry = tk.Entry(janela)
        historico_entry.grid(row=2, column=1)

        tk.Label(janela, text="Tratamento:").grid(row=3, column=0)
        tratamento_entry = tk.Entry(janela)
        tratamento_entry.grid(row=3, column=1)

        def criar_registro_usuario():
            criar_registro(nome_entry.get(), historico_entry.get(), tratamento_entry.get(), usuario_id)

        tk.Button(janela, text="Criar Registro", command=criar_registro_usuario).grid(row=4, column=1)

        # Tela de visualização de registro
        tk.Label(janela, text="ID do Registro para Visualizar:").grid(row=5, column=0)
        id_registro_entry = tk.Entry(janela)
        id_registro_entry.grid(row=5, column=1)

        def visualizar():
            visualizar_registro(id_registro_entry.get())

        tk.Button(janela, text="Visualizar Registro", command=visualizar).grid(row=6, column=1)

        tk.Label(janela, textvariable=resultado).grid(row=7, column=0, columnspan=2)

    # Iniciar tela de login
    tela_login()

    # Iniciar o loop da interface gráfica
    janela.mainloop()


# Iniciar a interface
iniciar_interface()