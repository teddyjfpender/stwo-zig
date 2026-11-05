import json,sys
rows=json.load(open(sys.argv[1]))['rows']
gas=json.load(open(sys.argv[2]))
G={b['block']:b['gas_used'] for b in gas['blocks']}
import itertools
def ols(X,y):
    # X list of lists (with intercept col), solve normal equations
    n=len(X[0])
    A=[[sum(x[i]*x[j] for x in X) for j in range(n)] for i in range(n)]
    b=[sum(x[i]*yy for x,yy in zip(X,y)) for i in range(n)]
    # gaussian
    M=[A[i]+[b[i]] for i in range(n)]
    for i in range(n):
        p=max(range(i,n),key=lambda r:abs(M[r][i]));M[i],M[p]=M[p],M[i]
        for r in range(n):
            if r!=i:
                f=M[r][i]/M[i][i]
                M[r]=[a-f*c for a,c in zip(M[r],M[i])]
    beta=[M[i][n]/M[i][i] for i in range(n)]
    pred=[sum(bi*xi for bi,xi in zip(beta,x)) for x in X]
    ss=sum((a-p)**2 for a,p in zip(y,pred));my=sum(y)/len(y);st=sum((a-my)**2 for a in y)
    return beta,1-ss/st,max(abs(a-p)/a for a,p in zip(y,pred))
I=[r['instructions']/1e6 for r in rows];S=[r['cpu_segments'] for r in rows];T=[r['truth_proofs'] for r in rows];L=[s+t for s,t in zip(S,T)]
g=[G[r['block']]/1e6 for r in rows]
for k in ['capture_s','setup_s','native_prove_s','recursion_s','request_s','native_verify_side_thread_s']:
    y=[r[k] for r in rows]
    for name,X in [('a+b*Minstr',[[1,i] for i in I]),('a+b*leaves',[[1,l] for l in L]),('a+b*seg+c*truth',[[1,s,t] for s,t in zip(S,T)]),('a+b*Minstr+c*truth',[[1,i,t] for i,t in zip(I,T)]),('a+b*Mgas',[[1,x] for x in g])]:
        beta,r2,mx=ols(X,y)
        print(k,name,[round(b,4) for b in beta],'R2=%.4f'%r2,'maxrel=%.3f'%mx)
    print()
r=[x for x in rows if x['block']==26235159][0];print(r['instructions'],G[26235159])
