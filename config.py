import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your_very_secret_key')
    DATABASE_URI = os.getenv('DATABASE_URI', 'https://cloud-profiler-demo-399610-default-rtdb.firebaseio.com')
    TOKEN = os.getenv('TOKEN')
    BASEURL = os.getenv('BASEURL')
    SUPABASE_URL = os.getenv('https://behqfhuhhplavrslpchi.supabase.co')
    SUPABASE_KEY = os.getenv('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJlaHFmaHVoaHBsYXZyc2xwY2hpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3MjA0Mzg0OTgsImV4cCI6MjAzNjAxNDQ5OH0.8NmlUlY9mzXMQvBtersRG8t4X4pVwgLNNulV_NwQOWA')