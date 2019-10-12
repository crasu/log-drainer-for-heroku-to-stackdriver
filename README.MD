# Heroku log drainer #

This little cloudfunction can forward logs from heroku to gcp's stackdriver

## Deploy log drainer with serverless ##

1. Configure gcloud cli tool with your gcp account
2. Install serverless
```
    npm install -g serverless
    npm install
```  
3. Install pyenv
```
    curl https://pyenv.run | bash
    pyenv install 3.7.3
    pyenv virtualenv 3.7.3 log-drainer-for-heroku-to-stackdriver
    pyenv activate log-drainer-for-heroku-to-stackdriver
```
4. Deploy
```
    serverless deploy
```
5. Add drain to your heroku app
```
    heroku drains:add https://<your-cloud-function-name>.cloudfunctions.net/stackdriver_handler -a your-app
```
