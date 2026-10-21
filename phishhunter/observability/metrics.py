REQUESTS=0
def inc_requests():
    global REQUESTS
    REQUESTS+=1
def prometheus_text(): return f"phishhunter_requests_total {REQUESTS}\n"
