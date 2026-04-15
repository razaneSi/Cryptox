import sqlite3
import os
from datetime import datetime

db_path = r'd:\cryptox\cryptox.db'
conn = sqlite3.connect(db_path)
cursor = conn.cursor()
cursor.execute('SELECT CURRENT_TIMESTAMP, datetime("now", "localtime")')
row = cursor.fetchone()
print(f'UTC (from DB): {row[0]}')
print(f'Local (from DB): {row[1]}')
print(f'Python datetime.now(): {datetime.now()}')
conn.close()
