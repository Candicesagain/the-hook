a = 'hippo'

b = 'hippo' # pragma: allowlist secret

c = 'hippo' #  allowlist secret

sql = """
select * from table
where name = "hippo" 
"""

def func():    
    # hippo  
    # hippo # pragma: allowlist secret
    # hippo allowlist
    return None