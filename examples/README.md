# Form Gate Examples

## Vanilla HTML

Open `vanilla-html/index.html` in a browser to see Form Gate in action.

```bash
cd examples/vanilla-html
# Open index.html in browser
```

## Running with Server

To test the full client+server flow:

```bash
# Terminal 1: Build client
cd packages/client-js
npm install
npm run build

# Terminal 2: Start server
cd packages/server-node
npm install
npm run build
node examples/server.js

# Open http://localhost:3000
```

## React

Coming soon...