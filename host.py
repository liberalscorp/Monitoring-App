import mysql.connector
import docker
from flask import Flask,request,render_template
import sqlite3
import re
from datetime import datetime
app= Flask(__name__)
def db_func(table_name,column_name,cursor,name,mydb):
	cursor.execute(f"SELECT ID FROM {table_name} WHERE {column_name}='{name}'")
	res=cursor.fetchall()
	if(res):
		return res[0][0]
	else:
		stat=f"INSERT INTO {table_name}({column_name}) VALUES ('{name}')"
		cursor.execute(stat)
		mydb.commit()
		cursor.execute(f"SELECT ID FROM {table_name} WHERE {column_name}='{name}'")
		res=cursor.fetchall()
		return res[0][0]

def logger(request):
	client=docker.DockerClient()
	container=client.containers.get("db-docker_mysql-development_1")
	ip_ad=container.attrs['NetworkSettings']['IPAddress']
	print(ip_ad)
#	ip_ad="172.17.0.2"
	mydb=mysql.connector.connect(
		host=ip_ad,
		user="guest",
		password="qwerty",
		database="testapp",
		port=3306,
		auth_plugin='mysql_native_password'
	)
	conn =mydb.cursor()
	tmp=""
	i=0
	for he in request.headers:
		if(i>5):
			tmp=tmp+" "+he[1]
		i=i+1
	method=request.method
	path=request.full_path
	body=request.get_data(as_text=True)
	dt=datetime.now()
	malicious=malcheck(body,path)
	path=db_func("Path","PATH",conn,path,mydb)
	ip=db_func("IP_Add","REMOTE_ADDR",conn,request.environ['REMOTE_ADDR'],mydb)
	method=db_func("Method","METHOD",conn,method,mydb)
	host=db_func("HOST","HOST",conn,request.headers['Host'],mydb)
	UA=db_func("Agent","USER_AGENT",conn,request.headers['User-Agent'],mydb)
	enc=db_func("ENCODING","ENCODING",conn,request.headers['Accept-Encoding'],mydb)
	Accept=db_func("Accept","ACCEPT",conn,request.headers['Accept'],mydb)
	lang=db_func("Language","LANGUAGE",conn,request.headers['Accept-Language'],mydb)
	val=(dt,ip,method,path,host,UA,Accept,lang,enc,tmp,body,malicious)
	conn.execute("INSERT INTO RealtimeLogs(Date_time,IP_id,Method_id,Path_id,Host_id,USER_AGENT_id,Accept_id,Language_id,Encoding_id,OTHER_HEADER,Body,Suspicious) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",val)
	mydb.commit()
	conn.close()
	mydb.close()
def malcheck(str1,str2):
	sp_check=re.compile('[(|)|$|{|}|<|>|(|)|\|~|:|%7[B-E]|%5[B-D]|%3[A-C]|%3E|%2[2-6]]')
	if(sp_check.search(str1)!=None):
		return 1
	if(sp_check.search(str2)!=None):
		return 1
	return 0
@app.errorhandler(404)
def not_found(e):
	logger(request)
	return render_template("404.html")

@app.route("/test",methods=['GET'])
def test():
	logger(request)
	return 'test'	
@app.route("/",methods=['GET'])
def home():
	logger(request)
	return render_template("form.html")
@app.route("/",methods=['POST'])
def check():
	logger(request)
	return request.form['Name']
if __name__=="__main__":
	app.run(host="0.0.0.0")
