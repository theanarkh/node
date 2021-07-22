const http = require('http');
function connect() {
    setTimeout(() => {
        http.get('http://119.28.74.111:8000/', (res) => {
            console.log(res.statusCode);
            connect();
        });
    }, 50);
}
connect();
