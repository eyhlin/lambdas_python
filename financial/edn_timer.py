import time
import sys

time.clock()
times = {}
frequency = {}
def timer(uid, t, cxt):
    if cxt=='s':
        if uid not in times:
            times[uid] = t
    elif cxt =='e':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
    elif cxt == 'fs':
        if uid not in times:
            times[uid] = t
            frequency[uid] = 0
    elif cxt == 'fex':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        frequency[uid]+=1
    elif cxt == 'fe':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        print (repr(uid)+'f: '+ repr(frequency[uid]))
    elif cxt == 'is':
        if uid not in times:
            times[uid] = t
            frequency[uid] = -1
    elif cxt == 'iex':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        frequency[uid]=1
    elif cxt == 'iez':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        frequency[uid]=0
    elif cxt == 'ie':
        if uid in times:
            r = t-times[uid]
            del times[uid]
            print (repr(uid)+': '+ repr(r))
        print (repr(uid)+'f: '+ repr(frequency[uid]))
    elif cxt == 'c':
        print (repr(uid)+'c: '+t)
        
        
if __name__ == '__main__':
    print('\n'.join(sorted(sys.path)))