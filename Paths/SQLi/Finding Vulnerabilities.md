Black Box Testing:
Tester given little information

1) Map the application:
   Visit the URL and walk throught all the pages that are avalible
   Make note of all the input vectors that potentially talk to the backend
   Understand how the application function
   Try to figure out the logic of the application
   Try to find subdomains on the application
   Enumerate directories and pages
Do all of this with Burp running silently on the background
Try to explore what the scanner cant already do
Scanner normally dont find logic flawks
Vulnerabilities can be embeded in pages that the scanner cant quote

2) Fuzz the application
   Submit SQL characters in the input vectors such as ``'`` or ``"`` or  ``#``  or ``//`` to look for anomalies
   Refine the query until you find the response that you want
   Error can give you usefull information about how the backend work:
	   Database and version and sometimes the query they are using

  Sometimes you dont get a error(Blind) so you need to submit boolean conditions such as `OR 1=1 and 0R 1=2` 
  Trigger time delays and wait to see it they work
  Submit OAST payloads designed to trigger and out-of-band network interaction and monitor the reaction

White Box Testing:
Tester given complete access and source code to the application
1) Enable web server login
2) Enable data base login
3) Map the application
	1) Visible functionality in the application
	2) Regex search on all instances in the code that talk to the database
4) Code Review
    Follow the code path for all input vectors
5) Test the vulnerability 

   
   
   