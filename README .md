# ShopNest - IDOR & Access Control Practice Lab

Ek realistic e-commerce site jisme IDOR aur related Broken Access Control bugs hain. Ye ek single `index.html` file hai, jo bina kisi server ke chalti hai.

## Test accounts
| Naam | Email | Password | Role |
|---|---|---|---|
| Alice Sharma | alice@shopnest.test | alice123 | user |
| Bob Verma | bob@shopnest.test | bob123 | user |
| Priya Nair | admin@shopnest.test | admin123 | admin |

## Kaise chalayein
- Local: `index.html` ko browser mein double-click karo.
- GitHub Pages: neeche ke steps follow karo.

## Developer tools
Footer mein **Developer tools** button hai. Isme:
- **Network:** har request ka log. Kisi entry par click karke use Repeater mein load karo.
- **Repeater:** method, path, headers aur body badal kar request bhejo.
- **Cookies:** session cookie (`user_id`) edit karo.

## GitHub Pages par deploy karna
1. GitHub par public repo banao, jaise `shopnest-idor-lab`.
2. `index.html` aur `README.md` upload karo.
3. `Settings > Pages` mein branch `main` aur folder `/ (root)` select karo.
4. Save karo. Link aayega: `https://<username>.github.io/shopnest-idor-lab/`

Ye link kisi ko bhi bhejo, wo bina install kiye practice kar sakta hai.

## Safety
- Ye lab intentionally insecure hai, lekin sab data fake hai aur koi real server nahi hai.
- Techniques sirf is lab par use karein. Kisi real website par bina permission ye karna illegal hai.
- Answer key (`ANSWERS.md`) repo mein na daalein agar log khud solve karein. Ise instructor ke paas rakhein.

## Burp Suite ke saath local run karna (recommended)
1. Python dependency install karo: `pip install flask`
2. Server chalao: `python app.py`
3. Burp mein proxy listener `127.0.0.1:8080` running hona chahiye.
4. Browser ko Burp se connect karo. Chrome ke liye Burp ka built-in browser sabse aasaan hai. Agar apna Chrome use karna hai to `--proxy-bypass-list="<-loopback>"` ke saath launch karo, kyunki default mein localhost bypass hota hai.
5. Browser mein `http://127.0.0.1:5000` kholo. Ab har API request Burp `HTTP history` mein dikhegi.

Local run mein requests real HTTP hain, isliye Burp Repeater mein Cookie header bhi change kar sakte ho. GitHub Pages par ye lab simulated mode mein chalta hai, jahan Burp requests nahi dekh sakta, isliye Burp practice ke liye local run hi use karo.
