#!/bin/bash
browserify immuto_browser.js --s Immuto -o immuto.js
mv immuto.js ../testing/browser/
