import dns.resolver

def enumerate_subdomains(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            print(f"A Record: {rdata}")
    except dns.resolver.NoAnswer:
        print("No A Record found")

    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            print(f"CNAME Record: {rdata}")
            if rdata.target != domain:  # Untuk menghindari looping tak terbatas pada CNAME yang mengarah ke dirinya sendiri
                enumerate_subdomains(str(rdata.target))
    except dns.resolver.NoAnswer:
        print("No CNAME Record found")

domain = "example.com"
enumerate_subdomains(domain)
