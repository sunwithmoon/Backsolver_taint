import pickle
import collections
import sys
def print_json(data, level=0):
    print('\t'*level+'{')
    for key in data:
        if type(data[key]) == dict:
            print('\t' * level + key + ':')
            print_json(data[key], level + 1)
        else:
            print("{}{}:\n{}{}".format('\t' * level, key, '\t' * (level + 1), data[key]))
    print('\t' * level + '}')

def recursive_hex_change(data):
    if type(data) == str:
        return data
    new_data = []
    for d in data:
        if isinstance(d, collections.Iterable):
            new_data.append(recursive_hex_change(d))
        elif type(d)==int:
            new_data.append(hex(d))
        else:
            new_data.append(d)
    return type(data)(new_data)



def dict2hex(data):
    hex_data = {}
    for key in data:
        new_key = hex(key) if type(key)==int else key
        if type(data[key])==dict:
            new_data = dict2hex(data[key])
        elif isinstance(data[key], collections.Iterable):
            new_data = recursive_hex_change(data[key])
        else:
            new_data = data[key]
        hex_data[new_key] = new_data
    return hex_data

def read_data(file):
    pk = "pickle_data/{}.pk".format(file)
    print(pk)
    fp = open(pk, "rb")
    data = pickle.load(fp)
    hex_data = dict2hex(data)
    return hex_data
    # print(data)


def diff(file1, file2):
    hex_data1 = read_data(file1)
    hex_data2 = read_data(file2)
    print(f"{file1} - {file2}\n\n", set(hex_data1)-set(hex_data2))
    print(f"{file2} - {file1}\n\n", set(hex_data2)-set(hex_data1))
    print(f"{file1} & {file2}\n\n", set(hex_data1)&set(hex_data2))

if __name__ == '__main__':
    # diff('jhead', 'jhead3')
    # exit()
    hex_data = read_data(sys.argv[1])
    print_json(hex_data)


# exit()
# wr=set()
# for addr in data:
#     wr.update(set(data[addr]["write_loc"]))
# wr = sorted(list(wr))
# for addr in wr:
#     print(hex(addr), end=" ")
# print("")
# print([(hex(s),hex(e)) for s,e in data[0xA62C]["from_branch"]])
