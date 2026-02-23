import os
from openai import OpenAI

# 1. READ YOUR KEY (Simulating the App's behavior)
KEY_PATH = "backend/data/llm_key.txt"
with open(KEY_PATH, "r") as f:
    api_key = f.read().strip()

print(f"Using Key: {api_key[:10]}...")

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_key,
)

try:
    response = client.chat.completions.create(
        model="openrouter/free",
        messages=[
            {"role": "user", "content": "Hello, respond with 'OpenRouter Working'"}
        ],
        extra_headers={
            "HTTP-Referer": "http://localhost:5173",
            "X-Title": "FYP-Debug",
        }
    )
    print("RESPONSE:", response.choices[0].message.content)
except Exception as e:
    print("ERROR DETECTED:", str(e))