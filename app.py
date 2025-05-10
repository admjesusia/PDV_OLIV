import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import io
import struct
import json
from datetime import datetime
import base64

# Configuração da página
st.set_page_config(
    page_title="PDV Backup Analyzer",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Classes do modelo de dados
class ArquivoBackup:
    def __init__(self, nome_arquivo="", tamanho_bytes=0):
        self.id = None
        self.nome_arquivo = nome_arquivo
        self.tamanho_bytes = tamanho_bytes
        self.assinatura = ""
        self.data_criacao = datetime.now()
        self.versao_formato = ""
        self.percentual_bytes_nulos = 0.0
        self.percentual_controle = 0.0
        self.percentual_ascii = 0.0
        self.percentual_unicode = 0.0
        self.numero_blocos = 0
        self.numero_regioes_nulas = 0
        self.capacidade_estimada = 0
        
class BlocoEstrutura:
    def __init__(self):
        self.id = None
        self.arquivo_id = None
        self.posicao_inicio = 0
        self.posicao_fim = 0
        self.tamanho = 0
        self.tipo = ""
        self.contem_texto = False
        self.contem_binario = False
        self.padroes_repetitivos = "{}"
        self.bytes_mais_comuns = "{}"
        self.assinatura_hex = ""
        
class NotaFiscal:
    def __init__(self):
        self.id = None
        self.bloco_id = None
        self.posicao_registro = 0
        self.numero = ""
        self.serie = ""
        self.data_emissao = datetime.now()
        self.valor_total = 0.0
        self.desconto = 0.0
        self.acrescimo = 0.0
        self.valor_final = 0.0
        self.cliente_id = None
        self.status = "ATIVA"
        self.tipo_nota = "VENDA"
        self.dados_brutos = bytes()

# Analisador do arquivo de backup
class PDVBackupAnalyzer:
    def __init__(self):
        self.arquivo = None
        self.blocos = []
        self.regioes_nulas = []
        self.notas_fiscais = []
        self.itens = []
        self.pagamentos = []
        self.clientes = []
        
    def carregar_arquivo(self, arquivo_bytes, nome_arquivo):
        """Carrega o arquivo para análise"""
        self.arquivo = ArquivoBackup(nome_arquivo, len(arquivo_bytes))
        
        # Analisar cabeçalho (assinatura HE3)
        if len(arquivo_bytes) >= 3 and arquivo_bytes[:3].decode('utf-8', errors='ignore') == "HE3":
            self.arquivo.assinatura = "HE3"
            # Análise básica do cabeçalho para versão
            self.arquivo.versao_formato = arquivo_bytes[3:7].decode('utf-8', errors='ignore').strip()
        else:
            st.error("Arquivo não possui a assinatura HE3!")
            return None
            
        # Análise básica de distribuição de bytes
        total_bytes = len(arquivo_bytes)
        bytes_nulos = sum(1 for b in arquivo_bytes if b == 0)
        bytes_controle = sum(1 for b in arquivo_bytes if b < 32)
        bytes_ascii = sum(1 for b in arquivo_bytes if 32 <= b <= 127)
        bytes_unicode = total_bytes - bytes_nulos - bytes_controle - bytes_ascii
        
        self.arquivo.percentual_bytes_nulos = (bytes_nulos / total_bytes) * 100
        self.arquivo.percentual_controle = (bytes_controle / total_bytes) * 100
        self.arquivo.percentual_ascii = (bytes_ascii / total_bytes) * 100
        self.arquivo.percentual_unicode = (bytes_unicode / total_bytes) * 100
        
        # Mapear regiões nulas
        self.mapear_regioes_nulas(arquivo_bytes)
        
        # Identificar blocos estruturais
        self.identificar_blocos(arquivo_bytes)
        
        # Tentativa de extrair notas fiscais
        self.extrair_notas_fiscais(arquivo_bytes)
        
        return self.arquivo
    
    def mapear_regioes_nulas(self, dados):
        """Identifica regiões de bytes nulos no arquivo"""
        tamanho_min = 20  # Tamanho mínimo para considerar uma região nula
        
        i = 0
        total_bytes = len(dados)
        
        while i < total_bytes:
            # Encontrar início de região nula
            while i < total_bytes and dados[i] != 0:
                i += 1
                
            inicio = i
            
            # Encontrar fim da região nula
            while i < total_bytes and dados[i] == 0:
                i += 1
                
            fim = i - 1
            
            # Se a região for grande o suficiente, registrá-la
            if fim - inicio + 1 >= tamanho_min:
                self.regioes_nulas.append({
                    'inicio': inicio,
                    'fim': fim,
                    'tamanho': fim - inicio + 1
                })
                
        self.arquivo.numero_regioes_nulas = len(self.regioes_nulas)
                
    def identificar_blocos(self, dados):
        """Identifica blocos estruturais entre regiões nulas"""
        # Ordenar regiões nulas por posição
        regioes_ordenadas = sorted(self.regioes_nulas, key=lambda r: r['inicio'])
        
        posicao_atual = 0
        
        # Identificar blocos entre regiões nulas
        for regiao in regioes_ordenadas:
            if regiao['inicio'] > posicao_atual:
                # Há um bloco de dados entre a posição atual e o início da região nula
                bloco = BlocoEstrutura()
                bloco.posicao_inicio = posicao_atual
                bloco.posicao_fim = regiao['inicio'] - 1
                bloco.tamanho = bloco.posicao_fim - bloco.posicao_inicio + 1
                
                # Análise básica do tipo de bloco
                if posicao_atual == 0:
                    bloco.tipo = "CABEÇALHO"
                else:
                    # Tentativa simples de identificar o tipo de bloco
                    # Em uma implementação real, seria necessária uma análise mais sofisticada
                    dados_bloco = dados[bloco.posicao_inicio:bloco.posicao_fim+1]
                    
                    # Verificar se contém texto
                    texto_ascii = sum(1 for b in dados_bloco if 32 <= b <= 127)
                    bloco.contem_texto = texto_ascii > len(dados_bloco) * 0.5
                    
                    # Verificar bytes não ASCII
                    bloco.contem_binario = any(b > 127 for b in dados_bloco)
                    
                    # Primeiros bytes em hex para identificação
                    hex_bytes = ''.join(f'{b:02x}' for b in dados_bloco[:16])
                    bloco.assinatura_hex = hex_bytes
                    
                    # Atribuir tipo com base em heurísticas simples
                    if posicao_atual < 1024:
                        bloco.tipo = "DEFINIÇÃO"
                    else:
                        bloco.tipo = "DADOS"
                
                self.blocos.append(bloco)
            
            # Atualizar posição atual para depois da região nula
            posicao_atual = regiao['fim'] + 1
        
        # Verificar se há um bloco final após a última região nula
        if posicao_atual < len(dados):
            bloco = BlocoEstrutura()
            bloco.posicao_inicio = posicao_atual
            bloco.posicao_fim = len(dados) - 1
            bloco.tamanho = bloco.posicao_fim - bloco.posicao_inicio + 1
            bloco.tipo = "DADOS"  # Assumir que é um bloco de dados
            
            self.blocos.append(bloco)
            
        self.arquivo.numero_blocos = len(self.blocos)
    
    def extrair_notas_fiscais(self, dados):
        """Tentativa de extrair notas fiscais dos blocos de dados"""
        # Simplificação: procurar padrões que possam indicar notas fiscais
        # Em uma implementação real, isso seria baseado na estrutura conhecida
        
        blocos_dados = [b for b in self.blocos if b.tipo == "DADOS"]
        
        for bloco in blocos_dados:
            # Dados do bloco
            dados_bloco = dados[bloco.posicao_inicio:bloco.posicao_fim+1]
            
            # Heurística simplificada: procurar por sequências que parecem números de NF
            # Um padrão comum é dígitos seguidos de uma série
            i = 0
            while i < len(dados_bloco) - 20:  # Garantir espaço suficiente para um registro
                # Verificar se temos uma sequência de dígitos
                if all(48 <= dados_bloco[i+j] <= 57 for j in range(6)):  # 6 dígitos
                    # Possível número de nota fiscal
                    nota = NotaFiscal()
                    nota.bloco_id = blocos_dados.index(bloco)
                    nota.posicao_registro = bloco.posicao_inicio + i
                    
                    # Extrair número (6 dígitos)
                    nota.numero = ''.join(chr(dados_bloco[i+j]) for j in range(6)).strip()
                    
                    # Extrair série (3 caracteres após o número)
                    nota.serie = ''.join(chr(dados_bloco[i+6+j]) for j in range(3)).strip()
                    
                    # Validações básicas
                    if nota.numero.isdigit() and len(nota.numero) > 0:
                        # Parece ser um número de nota válido
                        # Em uma implementação real, extrairíamos mais campos
                        
                        # Extrair valor (simulação)
                        try:
                            valor_bytes = dados_bloco[i+10:i+18]
                            # Tentativa de interpretação como float (simplificada)
                            valor_str = ''.join(chr(b) for b in valor_bytes if 32 <= b <= 127)
                            if valor_str.replace('.', '', 1).isdigit():
                                nota.valor_total = float(valor_str)
                                nota.valor_final = nota.valor_total
                            
                            # Se houve sucesso na extração do valor
                            if nota.valor_total > 0:
                                self.notas_fiscais.append(nota)
                        except:
                            pass  # Falha na extração do valor, ignorar
                
                i += 1  # Avançar para o próximo byte
    
    def exportar_para_csv(self):
        """Exporta os dados extraídos para DataFrames, que podem ser salvos como CSV"""
        # DataFrame de metadados do arquivo
        df_arquivo = pd.DataFrame([{
            'nome_arquivo': self.arquivo.nome_arquivo,
            'tamanho_bytes': self.arquivo.tamanho_bytes,
            'assinatura': self.arquivo.assinatura,
            'versao': self.arquivo.versao_formato,
            'percentual_bytes_nulos': self.arquivo.percentual_bytes_nulos,
            'percentual_controle': self.arquivo.percentual_controle,
            'percentual_ascii': self.arquivo.percentual_ascii,
            'percentual_unicode': self.arquivo.percentual_unicode,
            'numero_blocos': self.arquivo.numero_blocos,
            'numero_regioes_nulas': self.arquivo.numero_regioes_nulas
        }])
        
        # DataFrame de blocos estruturais
        df_blocos = pd.DataFrame([{
            'id': i,
            'posicao_inicio': b.posicao_inicio,
            'posicao_fim': b.posicao_fim,
            'tamanho': b.tamanho,
            'tipo': b.tipo,
            'contem_texto': b.contem_texto,
            'contem_binario': b.contem_binario,
            'assinatura_hex': b.assinatura_hex
        } for i, b in enumerate(self.blocos)])
        
        # DataFrame de regiões nulas
        df_regioes = pd.DataFrame(self.regioes_nulas)
        
        # DataFrame de notas fiscais
        df_notas = pd.DataFrame([{
            'id': i,
            'bloco_id': n.bloco_id,
            'posicao': n.posicao_registro,
            'numero': n.numero,
            'serie': n.serie,
            'valor_total': n.valor_total,
            'valor_final': n.valor_final
        } for i, n in enumerate(self.notas_fiscais)])
        
        return {
            'arquivo': df_arquivo,
            'blocos': df_blocos,
            'regioes': df_regioes,
            'notas': df_notas
        }
    
    def gerar_mapa_densidade(self, dados, tamanho_bloco=1024):
        """Gera um mapa de densidade de bytes por região do arquivo"""
        total_blocos = (len(dados) + tamanho_bloco - 1) // tamanho_bloco
        mapa = []
        
        for i in range(total_blocos):
            inicio = i * tamanho_bloco
            fim = min((i + 1) * tamanho_bloco - 1, len(dados) - 1)
            bloco_dados = dados[inicio:fim+1]
            
            bytes_nulos = sum(1 for b in bloco_dados if b == 0)
            bytes_controle = sum(1 for b in bloco_dados if b < 32 and b != 0)
            bytes_ascii = sum(1 for b in bloco_dados if 32 <= b <= 127)
            bytes_unicode = len(bloco_dados) - bytes_nulos - bytes_controle - bytes_ascii
            
            mapa.append({
                'inicio': inicio,
                'fim': fim,
                'densidade_nulos': bytes_nulos / len(bloco_dados),
                'densidade_controle': bytes_controle / len(bloco_dados),
                'densidade_ascii': bytes_ascii / len(bloco_dados),
                'densidade_unicode': bytes_unicode / len(bloco_dados)
            })
            
        return pd.DataFrame(mapa)

# Interface do Streamlit
def main():
    st.title("PDV Backup Analyzer")
    st.sidebar.header("Opções")
    
    # Opções de navegação
    pagina = st.sidebar.radio(
        "Selecione uma opção:",
        ["Upload de Arquivo", "Análise Estrutural", "Visualização de Dados", "Exportação", "Sobre"]
    )
    
    # Estado da sessão para armazenar dados entre navegações
    if 'arquivo_bytes' not in st.session_state:
        st.session_state.arquivo_bytes = None
        st.session_state.nome_arquivo = None
        st.session_state.analisador = None
        st.session_state.resultados = None
        st.session_state.df_mapa_densidade = None
    
    # Página de upload
    if pagina == "Upload de Arquivo":
        st.header("Upload de Arquivo de Backup PDV")
        
        arquivo = st.file_uploader("Selecione o arquivo de backup (.bk)", type=['bk', 'dat', 'bin', 'backup'])
        
        if arquivo is not None:
            st.session_state.arquivo_bytes = arquivo.getvalue()
            st.session_state.nome_arquivo = arquivo.name
            
            st.success(f"Arquivo '{arquivo.name}' carregado com sucesso! ({len(st.session_state.arquivo_bytes)} bytes)")
            
            # Iniciar análise
            if st.button("Analisar Arquivo"):
                with st.spinner("Analisando arquivo..."):
                    analisador = PDVBackupAnalyzer()
                    resultado = analisador.carregar_arquivo(
                        st.session_state.arquivo_bytes, 
                        st.session_state.nome_arquivo
                    )
                    
                    if resultado:
                        st.session_state.analisador = analisador
                        st.session_state.resultados = analisador.exportar_para_csv()
                        st.session_state.df_mapa_densidade = analisador.gerar_mapa_densidade(
                            st.session_state.arquivo_bytes
                        )
                        
                        st.success("Análise concluída! Navegue para 'Análise Estrutural' para ver os resultados.")
                    else:
                        st.error("Falha na análise do arquivo.")
    
    # Página de análise estrutural
    elif pagina == "Análise Estrutural":
        st.header("Análise Estrutural do Arquivo")
        
        if st.session_state.analisador is None:
            st.warning("Nenhum arquivo foi analisado. Faça o upload e a análise primeiro.")
            return
            
        # Exibir resumo da análise
        st.subheader("Resumo do Arquivo")
        st.dataframe(st.session_state.resultados['arquivo'])
        
        # Visualização da distribuição de bytes
        st.subheader("Distribuição de Bytes")
        
        # Criar gráfico de pizza para distribuição
        if st.session_state.resultados['arquivo'] is not None:
            arquivo_info = st.session_state.resultados['arquivo'].iloc[0]
            
            fig, ax = plt.subplots(figsize=(8, 6))
            labels = ['Bytes Nulos', 'Bytes de Controle', 'ASCII', 'Unicode/Outros']
            sizes = [
                arquivo_info['percentual_bytes_nulos'],
                arquivo_info['percentual_controle'] - arquivo_info['percentual_bytes_nulos'],
                arquivo_info['percentual_ascii'],
                arquivo_info['percentual_unicode']
            ]
            
            # Ajustar valores negativos
            sizes = [max(0, s) for s in sizes]
            
            colors = ['#f0f0f0', '#c8e6c9', '#bbdefb', '#ffcc80']
            explode = (0.1, 0, 0, 0)
            
            ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
                  shadow=True, startangle=90)
            ax.axis('equal')
            plt.title('Distribuição de Bytes no Arquivo')
            
            st.pyplot(fig)
        
        # Exibir blocos estruturais
        st.subheader("Blocos Estruturais Identificados")
        st.dataframe(st.session_state.resultados['blocos'])
        
        # Exibir regiões nulas
        st.subheader("Regiões Nulas Identificadas")
        st.dataframe(st.session_state.resultados['regioes'])
        
        # Mapa de calor da densidade de bytes
        st.subheader("Mapa de Densidade de Bytes")
        
        if st.session_state.df_mapa_densidade is not None:
            df_mapa = st.session_state.df_mapa_densidade
            
            # Criar visualização de mapa de calor
            fig, ax = plt.subplots(figsize=(14, 6))
            
            # Preparar dados para heatmap
            heatmap_data = df_mapa[['densidade_nulos', 'densidade_controle', 
                                    'densidade_ascii', 'densidade_unicode']].values.T
            
            # Criar o heatmap
            sns.heatmap(heatmap_data, cmap='viridis', ax=ax)
            
            # Configurar labels
            ax.set_yticks(np.arange(4) + 0.5)
            ax.set_yticklabels(['Nulos', 'Controle', 'ASCII', 'Unicode'])
            
            # X axis: mostrar posições em KB
            posicoes_kb = [f"{int(pos/1024)}KB" for pos in df_mapa['inicio']]
            ax.set_xticks(np.linspace(0, len(posicoes_kb)-1, min(20, len(posicoes_kb))))
            ax.set_xticklabels([posicoes_kb[int(i)] for i in np.linspace(0, len(posicoes_kb)-1, min(20, len(posicoes_kb)))])
            
            plt.title('Mapa de Densidade de Bytes ao Longo do Arquivo')
            plt.xlabel('Posição no Arquivo')
            plt.ylabel('Tipo de Byte')
            
            st.pyplot(fig)
            
            # Visualização da estrutura como gráfico de barras
            st.subheader("Visualização da Estrutura do Arquivo")
            
            # Criar figura para visualização de blocos e regiões nulas
            fig, ax = plt.subplots(figsize=(14, 6))
            
            # Plotar blocos
            for i, bloco in st.session_state.resultados['blocos'].iterrows():
                cor = 'blue' if bloco['tipo'] == 'CABEÇALHO' else 'green' if bloco['tipo'] == 'DEFINIÇÃO' else 'red'
                alpha = 0.7
                
                # Plotar barra representando o bloco
                ax.barh(0, bloco['tamanho'], left=bloco['posicao_inicio'], color=cor, alpha=alpha)
                
                # Adicionar label se o bloco for grande o suficiente
                if bloco['tamanho'] > st.session_state.arquivo_bytes.shape[0] * 0.05:
                    pos_x = bloco['posicao_inicio'] + bloco['tamanho'] / 2
                    ax.text(pos_x, 0, bloco['tipo'], ha='center', va='center', color='white', fontweight='bold')
            
            # Plotar regiões nulas
            for i, regiao in st.session_state.resultados['regioes'].iterrows():
                # Plotar barra representando a região nula
                ax.barh(0, regiao['tamanho'], left=regiao['inicio'], color='gray', alpha=0.5)
            
            # Configurar eixos
            ax.set_yticks([])
            ax.set_xlabel('Posição no Arquivo (bytes)')
            ax.set_title('Estrutura do Arquivo')
            
            # Ajustar limites do eixo x
            ax.set_xlim(0, len(st.session_state.arquivo_bytes))
            
            st.pyplot(fig)
    
    # Página de visualização de dados
    elif pagina == "Visualização de Dados":
        st.header("Visualização de Dados Extraídos")
        
        if st.session_state.analisador is None:
            st.warning("Nenhum arquivo foi analisado. Faça o upload e a análise primeiro.")
            return
            
        # Exibir notas fiscais extraídas
        st.subheader("Notas Fiscais Identificadas")
        
        if len(st.session_state.resultados['notas']) > 0:
            st.dataframe(st.session_state.resultados['notas'])
            
            # Estatísticas básicas
            st.subheader("Estatísticas das Notas Fiscais")
            
            df_notas = st.session_state.resultados['notas']
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Total de Notas", len(df_notas))
                
            with col2:
                if 'valor_total' in df_notas.columns and len(df_notas) > 0:
                    total = df_notas['valor_total'].sum()
                    st.metric("Valor Total (R$)", f"{total:.2f}")
                
            with col3:
                if 'valor_total' in df_notas.columns and len(df_notas) > 0:
                    media = df_notas['valor_total'].mean()
                    st.metric("Valor Médio (R$)", f"{media:.2f}")
            
            # Visualização de distribuição de valores
            if 'valor_total' in df_notas.columns and len(df_notas) > 0:
                st.subheader("Distribuição de Valores")
                
                fig, ax = plt.subplots(figsize=(10, 6))
                sns.histplot(df_notas['valor_total'], bins=20, kde=True, ax=ax)
                plt.title('Distribuição dos Valores das Notas Fiscais')
                plt.xlabel('Valor (R$)')
                plt.ylabel('Frequência')
                
                st.pyplot(fig)
        else:
            st.info("Nenhuma nota fiscal foi identificada no arquivo.")
            
            # Opção para tentar extrair manualmente
            st.subheader("Extração Manual")
            st.write("Você pode tentar extrair dados especificando parâmetros manualmente:")
            
            col1, col2 = st.columns(2)
            
            with col1:
                bloco_selecionado = st.selectbox(
                    "Selecione um bloco para análise:",
                    options=st.session_state.resultados['blocos']['id'],
                    format_func=lambda x: f"Bloco {x} ({st.session_state.resultados['blocos'].loc[x, 'tipo']})"
                )
            
            with col2:
                tamanho_registro = st.number_input("Tamanho estimado do registro (bytes)", min_value=10, value=100)
            
            if st.button("Tentar Extração Manual"):
                st.info("Funcionalidade de extração manual não implementada nesta versão simplificada.")
    
    # Página de exportação
    elif pagina == "Exportação":
        st.header("Exportação de Dados")
        
        if st.session_state.analisador is None:
            st.warning("Nenhum arquivo foi analisado. Faça o upload e a análise primeiro.")
            return
            
        # Opções de exportação
        formato = st.radio("Selecione o formato de exportação:", ["CSV", "JSON", "Excel"])
        
        # Selecionar dados para exportar
        st.subheader("Selecione os dados para exportar:")
        
        col1, col2 = st.columns(2)
        
        with col1:
            exp_resumo = st.checkbox("Resumo do Arquivo", value=True)
            exp_blocos = st.checkbox("Blocos Estruturais", value=True)
        
        with col2:
            exp_regioes = st.checkbox("Regiões Nulas", value=True)
            exp_notas = st.checkbox("Notas Fiscais", value=True)
        
        # Botão de exportação
        if st.button("Exportar Dados"):
            # Preparar dados para exportação
            dados_export = {}
            
            if exp_resumo:
                dados_export['resumo'] = st.session_state.resultados['arquivo']
            
            if exp_blocos:
                dados_export['blocos'] = st.session_state.resultados['blocos']
            
            if exp_regioes:
                dados_export['regioes'] = st.session_state.resultados['regioes']
            
            if exp_notas:
                dados_export['notas'] = st.session_state.resultados['notas']
            
            # Criar arquivo para download
            if formato == "CSV":
                # Para CSV, criar um arquivo ZIP com múltiplos CSVs
                zip_buffer = io.BytesIO()
                
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for nome, df in dados_export.items():
                        csv_data = df.to_csv(index=False).encode('utf-8')
                        zip_file.writestr(f"{nome}.csv", csv_data)
                
                zip_buffer.seek(0)
                b64 = base64.b64encode(zip_buffer.read()).decode()
                
                href = f'<a href="data:application/zip;base64,{b64}" download="pdv_backup_analysis.zip">Baixar arquivos CSV (ZIP)</a>'
                st.markdown(href, unsafe_allow_html=True)
                
            elif formato == "JSON":
                # Para JSON, criar um único arquivo JSON
                json_data = {}
                
                for nome, df in dados_export.items():
                    json_data[nome] = json.loads(df.to_json(orient='records'))
                
                json_str = json.dumps(json_data, indent=2)
                b64 = base64.b64encode(json_str.encode()).decode()
                
                href = f'<a href="data:application/json;base64,{b64}" download="pdv_backup_analysis.json">Baixar arquivo JSON</a>'
                st.markdown(href, unsafe_allow_html=True)
                
            elif formato == "Excel":
                # Para Excel, criar uma única planilha com múltiplas abas
                excel_buffer = io.BytesIO()
                
                with pd.ExcelWriter(excel_buffer) as writer:
                    for nome, df in dados_export.items():
                        df.to_excel(writer, sheet_name=nome, index=False)
                
                excel_buffer.seek(0)
                b64 = base64.b64encode(excel_buffer.read()).decode()
                
                href = f'<a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64}" download="pdv_backup_analysis.xlsx">Baixar arquivo Excel</a>'
                st.markdown(href, unsafe_allow_html=True)
    
    # Página sobre
    elif pagina == "Sobre":
        st.header("Sobre o PDV Backup Analyzer")
        
        st.markdown("""
        ## PDV Backup Analyzer
        
        Esta aplicação foi projetada para analisar arquivos de backup de PDV (Ponto de Venda) no formato HE3, 
        extraindo informações estruturais e dados de notas fiscais.
        
        ### Funcionalidades:
        
        - **Análise Estrutural**: Identifica a estrutura do arquivo, incluindo blocos de dados e regiões nulas.
        - **Extração de Dados**: Extrai informações de notas fiscais, itens, pagamentos e clientes.
        - **Visualização**: Fornece visualizações interativas da estrutura e dos dados extraídos.
        - **Exportação**: Permite exportar os dados analisados em diversos formatos.
        
        ### Tecnologias utilizadas:
        
        - **Streamlit**: Framework para criação de aplicações web com Python.
        - **Pandas**: Manipulação e análise de dados.
        - **Matplotlib/Seaborn**: Visualização de dados.
        - **NumPy**: Operações numéricas.
        
        ### Modelo de Dados:
        
        O sistema utiliza um modelo de dados relacional com as seguintes entidades principais:
        
        - **ArquivoBackup**: Metadados do arquivo de backup completo.
        - **BlocoEstrutura**: Blocos estruturais identificados no arquivo.
        - **RegiaoNula**: Regiões de bytes nulos (separadores/espaço reservado).
        - **NotaFiscal**: Registros de notas fiscais extraídos.
        - **ItemNotaFiscal**: Itens individuais de cada nota fiscal.
        - **PagamentoNotaFiscal**: Formas de pagamento associadas às notas.
        - **Cliente**: Dados de clientes referenciados nas notas.
        
        ### Limitações da versão atual:
        
        - Detecção automática limitada de estruturas complexas.
        - Suporte parcial para extração de notas fiscais.
        - Sem suporte para reempacotamento de arquivos modificados.
        
        ---
        
        Desenvolvido como parte de um projeto de análise e transformação de dados de PDV.
        """)

# Executar a aplicação
if __name__ == "__main__":
    main()
