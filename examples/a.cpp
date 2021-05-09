#include <iostream>

using namespace std;

class A{
    public:
    int x_a;
    virtual int f_a()=0;
};

class B : public A{
    public:
    int x_b;
    int f_a(){x_a = 0;}
    virtual int f_b(){this->f_a();}
};
class Z{
    public:
    virtual int f_z1(){cout << "f_z1";}
    virtual int f_z2(){cout << "f_z2";}
};

class C: public B, public Z{
    public:
    int f_a(){x_a = 5;}
    int x_c;
    int f_c(){x_c = 0;}
    virtual int f_z1(){cout << "f_z3";}
};


int main()
{
    C *c = new C();
    c->f_a();
    c->f_b();
    c->f_z1();
    c->f_z2();
    
    return 0;
}
