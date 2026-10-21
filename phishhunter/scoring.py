def explain(score:int)->str:
    if score>=80:return "Critical review recommended"
    if score>=60:return "High risk"
    if score>=35:return "Medium risk"
    return "Low risk"
