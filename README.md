# immuto.js

#### Immuto's JavaScript library for record creation and verification.

## Documentation
You can find complete documentation <a href="https://www.immuto.io/api-documentation"> here</a>. 

## Installation

### NodeJS
```
npm install immuto --save
```

### Browser
You may download a pre-built version by looking at the "Releases" tab. Include
in an HTML page as follows:
```
<script src="immuto.js"></script>
```

If you would like to build the browser code from scratch, you will need NPM and Browserify:
```
git clone https://www.github.com/immuto-inc/immuto.js
cd browser
npm install
browserify immuto_browser.js --s Immuto -o immuto.js
```
