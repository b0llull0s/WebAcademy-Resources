Primary Defenses:
	Use of prepared statements (Parameterized Queries)
		Build the SQL statement is performed in two steps:
			specify the query structure with placeholder for each user input
			specify the content for each placeholder
	Use of Stored Procedures (partial)
		Batch of statements grouped together and stored in the database
		Still need to be called in a parameterized way
	Whitelist Input Validation (partial)
		Defining what values are authorized. Everyrhing else is considered unauthorized.
		Useful for values that cannot be specified as parameter placeholders, such as the table  name.
	Escaping All User Supplied Input (partial)
		Last resort
Addiotional Defenses:
	Enforcing Least privilege
		The application should use the lowest possible level of privilages when accesing the database
		Remove unnecessary default functionaly
		Ensure CIS benchmark for the database in use is applied
		All vendor-issued security patches should be applied in a timely fashion 
	Performing Whitelist input validation as a secondary defense
		
