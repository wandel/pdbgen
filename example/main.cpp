#include <stdint.h>
#include <string.h>

struct Person
{
    char *name;
    int age;
};

bool compare(Person &one, Person &two)
{
    if (strcmp(one.name, two.name) == 0)
    {
        return one.age == two.age;
    }
    return false;
}

int main()
{
    Person one = {0};
    one.name = "bill";
    one.age = 10;
    Person two = {0};
    two.name = "bob";
    two.age = 20;

    if (compare(one, two))
    {
        return 0;
    }

    return 1;
}