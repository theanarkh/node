const http = require('http');
function connect() {
    setTimeout(() => {
        http.get('http://localhost:8000/', (res) => {
            console.log(res.statusCode);
            connect();
        });
    }, 50);
}
connect();
