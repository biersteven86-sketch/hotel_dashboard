module.exports = {
  apps: [{
    name: "hotel-web",
    script: "/home/steven/hotel_dashboard/web/server.js",
    instances: 1,
    exec_mode: "fork",
    watch: false,
    autorestart: true,
    max_restarts: 20,
    kill_timeout: 5000,
    env: {
      PORT: "3011",
      NODE_ENV: "production"
    },
    out_file: "/home/steven/.pm2/logs/hotel-web-out.log",
    error_file: "/home/steven/.pm2/logs/hotel-web-error.log"
  }]
}
