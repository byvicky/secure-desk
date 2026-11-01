from securedesk.schemas import Category, Priority
KEYWORDS: dict[Category, tuple[str,...]] = {
 "seguranca":("phishing","malware","ransomware","vazamento","invasao","suspeito","virus"),
 "acesso":("senha","login","bloqueado","permissao","mfa","autenticacao"),
 "rede":("internet","wifi","wi-fi","vpn","rede","conexao","servidor"),
 "hardware":("notebook","computador","teclado","monitor","impressora","equipamento"),
 "software":("sistema","aplicativo","programa","erro","instalar","atualizacao"),
}
def normalize(text:str)->str:
    return text.lower().translate(str.maketrans("áàãâéêíóôõúç","aaaaeeiooouc"))
def classify(title:str,description:str,supplied:Category|None=None)->Category:
    if supplied:return supplied
    text=normalize(title+" "+description)
    scores={c:sum(k in text for k in words) for c,words in KEYWORDS.items()}
    best=max(scores,key=scores.get)
    return best if scores[best] else "outro"
def prioritize(title:str,description:str,category:Category)->Priority:
    text=normalize(title+" "+description)
    if category=="seguranca" or any(x in text for x in ("ransomware","vazamento","invasao","malware","phishing")):return "critica"
    if any(x in text for x in ("sem acesso","parado","indisponivel","todos os usuarios","servidor")):return "alta"
    if any(x in text for x in ("erro","falha","lento","nao funciona")) or category in {"rede","acesso"}:return "media"
    return "baixa"
def analyze(title:str,description:str,supplied:Category|None=None)->tuple[Category,Priority]:
    category=classify(title,description,supplied)
    return category,prioritize(title,description,category)
