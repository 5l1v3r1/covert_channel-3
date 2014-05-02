'''
It runs a selenium browser and emulates gmail use for testing the throughput of Denali
'''

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

driver = webdriver.Firefox()
driver.get('https://www.gmail.com')
#assert 'Yahoo!' in browser.title
email = driver.find_element_by_id('Email')
email.send_keys('')
paswd = driver.find_element_by_id('Passwd')
paswd.send_keys('')
signin=driver.find_element_by_id("signIn")
signin.click()
driver.implicitly_wait(5)

while True:
    for i in range(1,6):
        string = '//table/tbody/tr['+str(i)+']/td[5]/div[@class=\'yW\']//span'
        print string
        s=driver.find_element_by_xpath(string)
        s.click()
        driver.back()
        driver.implicitly_wait(3)

driver.stop_client()

