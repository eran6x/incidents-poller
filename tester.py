import datetime

# easy method to retrieve new dates and loop each to get incidents and print them. 
# this is suitable for past incidents

def loopdays():
    date1 = datetime.date(2021, 9, 25)
    date2 = datetime.date(2022, 10, 8)
    day = datetime.timedelta(days=1)

    while (date1 <= date2):
        print(date1.strftime('%Y/%m/%d'))
        date1 = date1 + day


# easy method to retrieve current (new) incidents 
#  every 5m wake up and get the incidents for calculated time frame 
# then write to file

def get_new_incidents():
    datenow = datetime.date



def main():
    loopdays


################################
if __name__ == "__main__":
    main()