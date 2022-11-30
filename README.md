
# JS Lookup
This project was made to speed up the bug bounty recon stages. 
It quickly scans the source code of the given URL and the javascript codes used on that page and finds the functions that are dangerous to use if the necessary precautions are not taken. 
It's not a payload generation tool or exploitation tool, it can only suggest relevant links for functions or web vulnerabilities.
## Installation & Usage

```javascript
git clone https://github.com/ichbinbork/js_lookup.git

pip install -r requirements.txt

python main.py -u[Endpoint] -w[Wordlist] 

```
JS lookup requires 2 parameters to run

``-u`` parameter must contain destination url

``-w`` parameter must contain malicious methods functions to search

  
## Output

Output of script looks like the following

```bash
  Javascript found on line 138 in source code
Found /flasgger_static/swagger-ui-bundle.js
https://httpbin.org/flasgger_static/swagger-ui-bundle.js
Might be dangerous function in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js
Possible Javascript Injection in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js
Look at the eval() function parameters. If parameters has user input, it is vulnerable to javascript injection
Possible payloads: eval(document.cookie), eval(document.domain), eval(document.location)
More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval
Might be dangerous function in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js        
Possible payloads: window.location = 'https://www.attecker_website.com'
Might cause Open redirection vulnerability in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js
More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/location
Might be dangerous function in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js        
setRequestHeader in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js
Possible payloads: xhr.setRequestHeader('X-Forwarded-For', ')
More info at https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader
Might be dangerous function in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js        
JSON.parse in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js
Possible payloads: JSON.parse('string')
More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse       
Might be dangerous function in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js        
JSON.parse in javascript file https://httpbin.org/flasgger_static/swagger-ui-bundle.js
Possible payloads: JSON.parse('string')
More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse       
Javascript found on line 139 in source code
Found /flasgger_static/swagger-ui-standalone-preset.js
https://httpbin.org/flasgger_static/swagger-ui-standalone-preset.js
```

  
## Feedback

If you have any feedback about script please contact me at berkerturk21@gmail.com or https://www.linkedin.com/in/berk-ert%C3%BCrk/
  