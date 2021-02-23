import json
import Server


def userinfo(users, reference, identity):
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            print(ip, user)
            break
        elif reference == 'id' and ip == identity:
            print(ip, user)
            break
    else:
        print('No user found')


def kick(users, reference, identity, mask='none'):
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            break
        elif reference == 'id' and ip == identity:
            break
    else:
        print('No user found')
        return

    user['connection'].close()
    if mask == 'none':
        Server.disseminate_message(ip, {'action': 'kick', 'user': user})
    elif mask == 'disconnect':
        Server.disseminate_message(ip, {'action': 'kick', 'user': user})


dispatch = {'userinfo': userinfo, 'kick': kick}
