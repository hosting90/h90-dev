import mysql.connector
from wildcard_generate import wildcard_request


def run():
	mydb = mysql.connector.connect(
		host="galera-db1.hosting90.cz",
		user="root",
		passwd="xyooZfUzthvQE",
		database="hosting"
	)

	mysql_select = mydb.cursor()

	mysql_select.execute("SELECT * FROM certificates WHERE expiration IS NULL OR expiration < date_add(now(), interval 1 month) ")

	myresult = mysql_select.fetchall()

	if not myresult:
		return None

	for record in myresult:
		projekt =  record[1]
		cn = record[2]
		expiration = record[3]
		certificate_pem = record[4]
		privkey_pem = record[5]

	#  print projekt, cn, expiration, certificate_pem, privkey_pem

		wildcard_output = wildcard_request(cn, projekt)
		if False in wildcard_output:
			return wildcard_output

		cn = wildcard_output[0]
		privkey_pem = wildcard_output[1]
		certificate_pem = wildcard_output[2]
		expiration = wildcard_output[3]

		#print wildcard_output


		mysql_write = mydb.cursor()
		mysql_write.execute("""
			UPDATE certificates
			SET certificate=%s, private_key=%s, expiration=%s
			WHERE cn=%s
		""", (certificate_pem, privkey_pem, expiration, cn))

		mydb.commit()
		print(mysql_write.rowcount, "record(s) affected")


print run()
