### Study Notes
[Authentication & Authorisation](https://github.com/getfutureproof/fp_guides_wiki/wiki/Authentication-and-Authorisation)

## Demo Repo
Please note the `master` branch of this repo contains demos for basic authentication and password hashing using `bcrypt`.

***For a set of starter code with no password encryption, please see the `starter` branch!***
***For demos using JWT tokens, please see the `jwt` branch!***

### Install and run
- clone repo and cd into folder 
- For the jwt demo, you wil need to create a `.env` file in the `express-api` folder and add a key of `SECRET` assigned anything you like eg `SECRET=my_super_secret`

### Start server & db
- `docker compose up` 
  
### Start client
There are two versions of the client, one written in pure HTML/CSS/JS and the other written in React. If you have not yet learned React, leave that one for now and come back in a few weeks! If you are coming back here after learning React, you may find it interesting to compare and contrast the approaches made in these demos. Remember there is very rarely only one way to acheive a goal so consider how the file structure (and component structure in the React app) could be altered to your taste / different requirements.

**Option A:** Pure HTML/CSS/JS
- `cd html-css-js-client`
- `http-server` (node) / (or just open the `index.html` file in your browser)

**Option B:** React
- `cd react-client`
- `npm install`
- `npm start`

### Stop server & db
- `docker compose down --volumes --remove-orphans`
  
### Stop client
- <kbd>Ctrl</kbd> + <kbd>C</kbd> (Options A & B)

# Exercises
- Add authentication to a new or existing app
    - Include password hashing as a minimum
    - If using a React app, implement at least one custom Route component

- Optionally: add persistance with either JWT tokens (try `jsonwebtoken`) or sessions (try `express-session`)
  
- Optionally: add 3rd party integrations using a library such as `passport`