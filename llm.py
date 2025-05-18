import argparse
import pathlib

import pymupdf4llm
from llama_index.core import StorageContext, VectorStoreIndex, load_index_from_storage, Settings
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.llms.ollama import Ollama

# embed_model = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L6-v2")
Settings.llm = Ollama(model="llama3.2", request_timeout=600.0)
Settings.embed_model = HuggingFaceEmbedding(model_name="intfloat/multilingual-e5-large")

def pdf_to_md(input_file_path: str, output_file_path: str):
  md_text = pymupdf4llm.to_markdown(input_file_path)
  pathlib.Path(output_file_path).write_bytes(md_text.encode())

def pdf_to_llamaindex(input_file_path: str, query: str = None):
  try:
    # Open the specified PDF file
    llama_reader = pymupdf4llm.LlamaMarkdownReader()
    llama_docs = llama_reader.load_data(input_file_path)

    index = VectorStoreIndex.from_documents(llama_docs)

    # storage_context = StorageContext.from_defaults(persist_dir="./storage")
    index.storage_context.persist(persist_dir="./storage")

  except Exception as e:
    print(f'Error: {e}')


def query_localllm(query: str):
  # 保存したインデックスのロード
  storage_context = StorageContext.from_defaults(persist_dir="./storage")
  loaded_index = load_index_from_storage(storage_context)

  # クエリエンジンの作成
  query_engine = loaded_index.as_query_engine()

  # クエリの実行
  response = query_engine.query(query)
  print(response)

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Display content of a PDF file using PyMuPDF4LLM and LlamaIndex')
  parser.add_argument('-m', '--mode', type=str, help='Path to the PDF file')
  parser.add_argument('-i', '--input_file', type=str, help='Path to the PDF file')
  parser.add_argument('-o', '--output_file', type=str, help='Path to the file')
  parser.add_argument('-q', '--query', type=str, help='Query to run against the PDF content', default=None)
  args = parser.parse_args()

  if args.mode == 'md':
    pdf_to_md(args.input_file, args.output_file)
  elif args.mode == 'llamaindex':
    pdf_to_llamaindex(args.input_file)
  elif args.mode == 'query':
    print(args.query)
    query_localllm(args.query)
