import sqlite3

def fix_db():
    conn = sqlite3.connect('threat_events.db')
    c = conn.cursor()
    # Replace repeated Multi-Stage: strings
    c.execute("UPDATE threat_events SET mitre_tactic = 'Multi-Stage: Discovery, Resource Development' WHERE mitre_tactic LIKE '%Multi-Stage: Multi-Stage:%'")
    conn.commit()
    conn.close()
    print('DB fixed')

if __name__ == '__main__':
    fix_db()
