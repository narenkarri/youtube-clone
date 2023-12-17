# YouTube Clone

> This is the frontend (VueJS) of the VueTube clone

## API

Backend RESTFUL API Repository [API](https://github.com/techreagan/youtube-clone-nodejs-api)

## Features

- Sign in / Sign Up to create channel
- Video
  - Upload video
  - Upload video thumbnail
  - Watch video
  - Increase Views
  - Like and dislike video
  - Download video
  - Comment & reply for video
  - Update video details
  - Delete video
- Subscribe to a channel
- View liked videos
- Trending
- Subscriptions
- History
  - Watch history
  - Search history
- Settings
  - Modify channel name and email
  - Change password
  - Upload channel avatar

## Project setup

Create .env.development.local for development then .env.production.local for production ready app.
Then put in your api URL

```
VUE_APP_URL=http://localhost:3001
```

### Install packages

```
npm install
```

### Compiles and hot-reloads for development

```
npm run serve
```

### Compiles and minifies for production

```
npm run build
```

### Lints and fixes files

```
npm run lint
```
