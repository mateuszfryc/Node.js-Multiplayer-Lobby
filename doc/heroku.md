## Heroku Instructions

### Prerequisites

- Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli).
- Ensure you are logged into Heroku:
  `bash
heroku login
`

### Creating a New App with Heroku CLI

Create a new app:
`bash
heroku create <app-name>
`

If you want Heroku to generate a name for the app:
`bash
heroku create
`

### Pulling from Heroku

To pull the latest code from Heroku:
`bash
heroku git:clone -a <app-name>
`

### Pushing to Heroku

Make sure your code changes are committed locally. Push to Heroku:
`bash
git push heroku main
`

If your default branch is `master`, use:
`bash
git push heroku master
`

### Adding Environment Variables

To add an environment variable:
`bash
heroku config:set <KEY>=<VALUE> -a <app-name>
`

Example:
`bash
heroku config:set DATABASE_URL=postgres://<user>:<password>@<host>:<port>/<db_name> -a <app-name>
`

### Removing Environment Variables

To remove an environment variable:
`bash
heroku config:unset <KEY> -a <app-name>
`

### Viewing Environment Variables

To list all environment variables:
`bash
heroku config -a <app-name>
`

This will display all environment variables set for your Heroku app.

### Deploying to Heroku

1. Make sure your `Procfile` is correctly configured.
2. Push your code to Heroku:
   `bash
git push heroku main
`
3. If your app uses PostgreSQL, ensure the add-on is installed:
   `bash
heroku addons:create heroku-postgresql:hobby-dev -a <app-name>
`

### Watching Logs in Real Time

To stream logs in real-time:
`bash
heroku logs --tail -a <app-name>
`

### Scaling Dynos

To scale the number of dynos:
`bash
heroku ps:scale web=<number> -a <app-name>
`

Example to scale to 2 dynos:
`bash
heroku ps:scale web=2 -a <app-name>
`

### Restarting the App

To restart all dynos:
`bash
heroku restart -a <app-name>
`

### Checking App Status

To view the current status of your app:
`bash
heroku ps -a <app-name>
`

### Database Migrations

If your app uses PostgreSQL and requires migrations, run:
`bash
heroku run npm run migrate -a <app-name>
`

### Running One-off Commands

To run a one-off command in your app’s environment:
`bash
heroku run <command> -a <app-name>
`

Example:
`bash
heroku run bash -a <app-name>
`

### Viewing Add-ons

To list all add-ons for your app:
`bash
heroku addons -a <app-name>
`

### Removing an Add-on

To remove an add-on:
`bash
heroku addons:destroy <addon-name> -a <app-name>
`

### Connecting to PostgreSQL

To access the PostgreSQL database via Heroku CLI:

`bash
heroku pg:psql -a <app-name>
`

1. This will open an interactive `psql` session where you can execute SQL queries.
2. Example commands in `psql`:

   - List all tables:
     `sql
\dt
`
   - Describe a specific table:
     `sql
\d <table-name>
`
   - Exit the session:
     `sql
\q
`

3. To run specific queries directly:
   `bash
heroku pg:psql -a <app-name> --command="<SQL-query>"
`

   Example:
   `bash
heroku pg:psql -a <app-name> --command="SELECT * FROM users;"
`
