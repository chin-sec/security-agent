from dotenv import load_dotenv
import os

load_dotenv()
print("QWEN_API_KEY:", os.getenv("QWEN_API_KEY")[:5] + "...")

