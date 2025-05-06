# Machine Problem 2


## Guarding the Gates: How We Defeated CSRF in a Flask
Cross-Site Request Forgery (CSRF) is the like the Trojan Horse of web security. It tricked a logged-in user's browser into making an unwanted request. It could be like submitting a form or clicking a button without them knowing.'

Imagine you're at your favorite coffee shop. You hand your phone to a friend to show them a funny meme but while you’re not looking, they sneak into your banking app and transfer $100 to themselves. Sneaky, right? The attacker does not need to steal you log in credentials. They just ride along using you existing session, like the greek soldiers inside the Trojan Horse.

Let's say that you are logged in into your social media account and an attacker sends you an image or a link that you clicked without hesitation, then BOOM!!! Your browser silently sends a POST request to the real site using your valid session cookie, and suddenly you’ve posted “I am gay” to 5,000 followers.

In the given Flask web app, we have two html file that accepts POST requests:
1. /login - where users input credentials
2. /posts - where logged-in users submit their posts
But both routes accept form data with zero CSRF protection. This means a third-party site could trick a user's browser into logging in or making posts on their behalf without permission.

## The CSRF Vaccine
First, we installed Flask-WTF (also added in the requirements.txt), this is a handy extension that injects a CSRF token into forms. After installing, we enabled CSRF protection in the app with this:
```
from flask_wtf import CSRFProtect
app.secret_key = secrets.token_hex()  # Needed for CSRF protection
csrf = CSRFProtect(app)
```
Modified all POST-handling forms to include `{{ csrf_token() }}`